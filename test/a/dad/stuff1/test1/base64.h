#ifndef BASE64_H    
#define BASE64_H    
                     
int Base64encode(char *encoded, const char *string, int len);
int Base64decode(char *bufplain, const char *bufcoded);
#endif 
