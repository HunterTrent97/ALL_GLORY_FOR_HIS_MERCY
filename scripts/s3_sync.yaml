#!/usr/bin/env python3

import argparse, os, threading, time, random
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED, as_completed
from datetime import datetime
import boto3, yaml
from boto3.s3.transfer import TransferConfig
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError, ReadTimeoutError, ConnectTimeoutError, ConnectionClosedError

def parse():
    p = argparse.ArgumentParser()
    p.add_argument("--config", required=True)
    return p.parse_args()

def load_cfg(path):
    with open(path) as f:
        return yaml.safe_load(f)

def load_state(path):
    return set(open(path).read().splitlines()) if os.path.exists(path) else set()

def save_state(state, path, key, lock):
    with lock:
        if key not in state:
            state.add(key)
            with open(path, "a") as f:
                f.write(key + "\n")

def log_fail(path, src, dst, err, lock):
    ts = datetime.utcnow().isoformat()+"Z"
    if isinstance(err, ClientError):
        code = err.response.get("Error", {}).get("Code")
        msg = err.response.get("Error", {}).get("Message")
    else:
        code = type(err).__name__
        msg = str(err)
    with lock:
        with open(path, "a") as f:
            f.write(f"timestamp={ts} | src={src} | dest={dst} | reason={code} | detail={msg}\n")

def list_objs(s3, bucket, prefix):
    p = s3.get_paginator("list_objects_v2")
    for page in p.paginate(Bucket=bucket, Prefix=prefix):
        for o in page.get("Contents", []):
            yield o["Key"], o["Size"]

def rel_key(k, prefix):
    return k[len(prefix.rstrip("/"))+1:] if prefix and k.startswith(prefix.rstrip("/")+"/") else k

def dest_key(src, srcp, dstp):
    r = rel_key(src, srcp)
    return f"{dstp.rstrip('/')}/{r}" if dstp else r

def exists(s3, bucket, key, size):
    try:
        return s3.head_object(Bucket=bucket, Key=key)["ContentLength"] == size
    except ClientError as e:
        if e.response["Error"]["Code"] in ["404","NoSuchKey","NotFound"]:
            return False
        raise

def retryable(e):
    if isinstance(e,(EndpointConnectionError,ReadTimeoutError,ConnectTimeoutError,ConnectionClosedError)):
        return True
    if isinstance(e,ClientError):
        return e.response["Error"]["Code"] in {
            "RequestTimeout","Throttling","SlowDown","InternalError","ServiceUnavailable"
        }
    return False

def expired(e):
    return isinstance(e,ClientError) and e.response["Error"]["Code"]=="ExpiredToken"

def backoff(base, maxv, attempt):
    time.sleep(min(maxv, base*(2**(attempt-1))) + random.random())

def process(s3,cfg,state,lock,stop,key,size,tx):
    dst = dest_key(key,cfg["source"].get("prefix",""),cfg["destination"].get("prefix",""))
    sf = cfg["execution"]["state_file"]
    ff = cfg["execution"]["fail_log_file"]
    db = cfg["destination"]["bucket"]
    sb = cfg["source"]["bucket"]

    if key in state: return "skip-local"

    try:
        if exists(s3,db,dst,size):
            save_state(state,sf,key,lock)
            return "skip-s3"
    except Exception as e:
        if expired(e): stop.set(); return "abort"
        log_fail(ff,key,dst,e,lock); return "fail"

    if cfg["execution"]["dry_run"]: return "dry"

    for i in range(1,cfg["execution"]["retryable_attempts"]+1):
        try:
            s3.copy({"Bucket":sb,"Key":key},db,dst,Config=tx,ExtraArgs=cfg.get("copy",{}).get("extra_args") or {})
            save_state(state,sf,key,lock)
            return "copied"
        except Exception as e:
            if expired(e):
                stop.set()
                return "abort"
            if retryable(e) and i < cfg["execution"]["retryable_attempts"]:
                backoff(cfg["execution"]["retry_backoff_base_seconds"],cfg["execution"]["retry_backoff_max_seconds"],i)
                continue
            log_fail(ff,key,dst,e,lock)
            return "fail"

def main():
    a = parse()
    cfg = load_cfg(a.config)

    s3 = boto3.client("s3", config=Config(
        retries={"mode":cfg["aws"]["retry_mode"],"max_attempts":cfg["aws"]["max_attempts"]},
        max_pool_connections=cfg["aws"]["max_pool_connections"]
    ))

    tx = TransferConfig(
        multipart_threshold=cfg["execution"]["multipart_threshold_mb"]*1024*1024,
        multipart_chunksize=cfg["execution"]["multipart_chunk_mb"]*1024*1024,
        max_concurrency=cfg["execution"]["per_file_concurrency"]
    )

    state = load_state(cfg["execution"]["state_file"])
    lock = threading.Lock()
    stop = threading.Event()

    results = {"copied":0,"fail":0,"skip-local":0,"skip-s3":0,"dry":0,"abort":0}

    with ThreadPoolExecutor(max_workers=cfg["execution"]["workers"]) as ex:
        inflight=set()
        count=0
        for k,s in list_objs(s3,cfg["source"]["bucket"],cfg["source"].get("prefix","")):
            if stop.is_set(): break
            if cfg["execution"]["limit"] and count>=cfg["execution"]["limit"]: break

            inflight.add(ex.submit(process,s3,cfg,state,lock,stop,k,s,tx))
            count+=1

            if len(inflight)>=cfg["execution"]["max_in_flight"]:
                done,inflight=wait(inflight,return_when=FIRST_COMPLETED)
                for f in done: results[f.result()]+=1

        for f in as_completed(inflight):
            results[f.result()]+=1

    print(results)

    if stop.is_set():
        raise SystemExit(2)

if __name__ == "__main__":
    main()
