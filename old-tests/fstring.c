
/* Make this hidden so that calls to this refer to it internally instead of using the plt */
/* Ok, this does not need to be made hidden.  The problem is that any function referenced
   externally by the main binary will now be forced out through the plt so that the function
   pointer would be consistent for the function.
   So we don't need __attribute__((__visibility__("hidden"))) because this only happens to
   enforce consistency.  Instead if we only reference the function we actually call from 
   the driver, we don't need to worry about this.
   Reference:
   https://stackoverflow.com/questions/36354247/how-do-i-force-gcc-to-call-a-function-directly-in-pic-code
   https://stackoverflow.com/questions/51227608/how-exactly-is-fno-semantic-interposition-different-than-fvisibility-prot?rq=1
   */
char* get_fstring_c(int index){
	if(index){
		return "one";
	}else{
		return "zero";
	}
}
