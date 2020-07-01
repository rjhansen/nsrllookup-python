# nsrllookup-python

## What is it?
A single-file module that lets you do NSRL RDS lookups in Python.

## How do I use it?
```python
from nsrllookup import NSRLLookup

nsrl = NSRLLookup()
nsrl.add_directory("/bin")
result = nsrl.run_query()

for kind in ["known", "unknown"]:
    print("{} files:".format(kind))
    for key in result[kind]:
        files = ", ".join(result[kind][key])
        print("\t{}: {}".format(key, files))
```

## That's a gross print statement.
It's not that bad.  The result given from running the query is a dictionary with two keys, `known` and `unknown`.  The former represents the data that resulted in an NSRL RDS hit; the latter represents the data that resulted in an NSRL RDS miss.

Once you access either `result["known"]` or `result["unknown"]`, you get another dictionary.  This dictionary maps MD5 hashes to the files that hashed out to that value.  (For instance, on many Linux systems `/bin/bzcmp` and `/bin/bzdiff` are the same file and will have identical MD5 values.)

Those files are stored as a set, not as a list.  This keeps us from ever having multiple copies of the same filename in our output: no matter how many times you add a file to the query, it'll only be queried once and will only be reported once.

So, `result["known"]` gives us the NSRL RDS hits; `result["known"]["some MD5 hash"]` gives the files which hashed out to `"some MD5 hash"` which resulted in hits.

## Is it open-source/free software?
It is: it's ISC-licensed.  Share and enjoy.