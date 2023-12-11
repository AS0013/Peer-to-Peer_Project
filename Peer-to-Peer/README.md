
## To run a Python server from within the *python/server* directory:
    python3 server.py ../../config.yaml

## To run a Python client from within the *python/server* directory:
    python3 client.py ../../config.yaml 

## To compile the C client from within the *src* directory:
    make

## To run C client from within the *src* directory:
    ./networking ../config.yaml

## To clean C client from within the *src* directory:
    make clean

## To check correctness of results from within the *src* directory:
    diff tiny.txt ../python/server/tiny.txt && diff hamlet.txt ../python/server/hamlet.txt
The above command should produce no output if everything has worked correctly
