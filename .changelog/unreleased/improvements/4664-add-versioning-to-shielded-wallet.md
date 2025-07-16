- Currently, the shielded wallet attempts to find a file and deserialize it, but of which are fallible. Upon failure, 
  a default (empty) wallet is created. This is fine if the file is missing, but causes unexpeceted behavior when we've changed
  the wallet format and deserialize fails. This PR changes the logic to the following:

  - If the file is missing, use a default
  - If deserialization fails, try to run a migration (this requires versioning shielded wallets)
  - If deserializing / migration fails, error out explicitly
  
  ([\#4664](https://github.com/anoma/namada/pull/4664))