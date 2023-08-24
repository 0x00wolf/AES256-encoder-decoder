## AES256-encoder-decoder
A command line tool written in Python that can generate 256-bit AES keys and uses cipher-feedback encryption to encode and decode files.

### The program has four modes.
**-h**    displays the help window  
**-e**    decrypts a file with a preexisting key  
**-d**    decrypts a file with a preexisting key  
**-k**    generates a 256-bit AES key and saves it as ./AES256key  

### Example usage:
**python3 encoder.py -e ./file.type ./key**  
**python3 encoder.py -d ./file.type.encrypted ./key**  
**python3 encoder.py -k**  

### Please note: 
The name of the file being unencrypted must end in '.encrypted' or the program will fail.
