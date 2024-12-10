# trusted-kms

This is the prototype of Trusted-KMS.

## Instance Deployment

If you want to deploy only a KMS instance for debug, use the following guide.

Firstly, need to generate a server side CA to sign client certificates.

```shell
cd test
openssl req \
    -x509 \
    -nodes \
    -days 365 \
    -newkey rsa:2048 \
    -keyout ca.key \
    -out ca.crt \
    -config ca.conf \
    -passin pass:

replace_section() {
    local replacement_file=$1
    local placeholder=$2
    local file_to_modify=$3

    content=$(sed 's:[:\/&]:\\&:g;s/$/\\n/' $replacement_file | tr -d '\n')
    sed -i "s/${placeholder}/${content}/g" "$file_to_modify"
}

cp ../config.toml.template config.toml
replace_section ca.key @CLIENT_CA_PRIVATE_KEY@ config.toml
replace_section ca.crt @CLIENT_CA_CERT@ config.toml
```

Then, launch the KMS
```shell
cd ..
make
./target/release/trusted-kms -c test/config.toml
```

Test requests
```shell
# Register a new client
cd test
./generate-key.sh
../target/release/client  -a http://127.0.0.1:9993 register client.key

# Then you can get the certificate of the client private key
# Suppose the cert is stored in `test/client.crt`

# Generate a CMK
target/release/client  -a https://127.0.0.1:9992 generate-cmk test/client.key client.crt server.crt 
```

## Fully deployment

The deployment requires [Confidential Containers](https://github.com/confidential-containers).

Once Confidential Containers is prepared, use the following command to deploy.

```shell
kubectl apply -f kms.yaml
```
