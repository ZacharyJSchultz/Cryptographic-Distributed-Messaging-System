# Cryptography Project

This is an adapted repository from a University of Pittsburgh cryptography project; this repo contains the re-uploaded code, as the original is private (hence, only a couple of commits).

This project houses a console-based distributed messaging system -- consisting of an Authentication Server, a Resource Server, and a Client. The project utilizes a client-server architecture to transmit end-to-end encrypted messages between clients in customizable group chats (or private messages), adhering to the latest cryptographic standards with handling for various real-world cryptographic threats.


## Authors

This project was developed by myself, ZacharyJSchultz, along with JordanShopp, yuz727, loweaidan5, and HWalk59.


## How To Run This Application

To run the project, the latest version of Java and Maven must be installed on the local machine. Furthermore, for the project to properly work, public/private key pairs for the AS and RS must be generated. To generate these keypairs, run ASKeyPairGen.java (found at ```src/main/java/com/ciphersquad/chat/AuthenticationServer/ASKeypairGen.java```) and RSKeyPairGen.java (found at ```src/main/java/com/ciphersquad/chat/ResourceServer/RSKeypairGen.java```). Note that for RSKeyPairGen.java, you must specify the IP of the server, as each server should have its own unique keypair.

Next, the RS, AS, and Client must all be run for the application to function properly. 

- First, one must clone the repository, and then run ```mvn compile``` in the main directory.
- To run the RS, type ```bash RS.bash``` in the main directory. Then follow any prompts on the terminal (i.e., asking for the IP of the machine and the port to run from)
- To run the AS, (from a new terminal window) type ```bash AS.bash``` in the main directory. Then follow any prompts on the terminal (i.e., specifying the port to run from)
- Lastly, to run the Client, (from a new terminal window) type ```bash main.bash``` in the main directory. Note: You can run as many clients as you'd like.


## How To Use This Application

For information on how to use this application (from the client side), please see doc/user_manual.pdf. 

For information on how this application works, please see doc/technician_guide.pdf. 

For information on our design decisions and threat analyses, please see the phase write-ups located in the /doc folder. 