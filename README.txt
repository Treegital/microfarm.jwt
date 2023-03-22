Generate the keys
-----------------

The private key needs to be without a password. (for now)

  $> openssl genrsa -out jwt.key 4096
  $> openssl rsa -in jwt.key -pubout -out jwt.pub
