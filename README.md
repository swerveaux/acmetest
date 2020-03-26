# ACME v2 Client in go

I had a need for something to automate updating certs from Let's Encrypt, preferably storing them in AWS Secrets
Manager, and preferred not to just shell out and run certbot to do so.   I found a few Go implementations, but they
all seemed to be using ACME v1, which Let's Encrypt no longer lets people create accounts for in their staging
environment.   In addition, most of the JWT libraries I found only supported compact serialization, whereas ACME
requires flattened serialization.   The stdlib had almost exactly what I needed, but in non-exported functions, so 
I cribbed a fair bit of that with some minor changes to get the JWT serialization I needed.

This code is fairly dependent on using AWS for both the DNS challenges and for where to store the key and cert.
That should be limited to secrets.go (where you could always just change addSecret to write to a file somewhere
or what have you), and route53.go, which is mostly complicated because of the way AWS does hosted zones.   This
should be easily adaptable to something else -- I say should because I originally planned to write this against
GCP only to find out they don't have a go SDK.   Which is weird.

## Usage

As it stands, this isn't intended for general usage, so it's not the most user friendly thing.   To switch 
between using Boulder, Let's Encrypt's staging environment, and their prod environment, change which constant
gets assigned to acmeURL in cmd/acmetest/main.go.   Then run that with the following required options:

  --contacts person1@example.com[,person2@example.com,...]
  --domains example.com[,anotherexample.com]
  
 You'll need to have some way to authenticate with AWS (probably keys in ~/.aws/credentials) and a hosted zone for
 each of the domains you want to get a cert for.   The IAM role pointed to by the credentials will need upsert and
 delete permissions for route53 and ListSecrets/AddSecrets for ASM.
 
 It starts by creating an account on Let's Encrypt with the contact emails provided on the command line.   Then it
 goes through the domains one by one, updating the TXT record set for the hosted zone with the challenge coming
 from Let's Encrypt.   As each of those passes, it then generates a key and requests a cert, then stores those
 in ASM as `ssl_<domain>.key` and `ssl_<domain>.crt`.   Then it exits.

And that's about it.