#------------SCRIPT TO GET A COMPLETE RECURSIVE DIFF B/W TWO FOLDERS---------------#

#Usage : ./diff.sh <directory1> <directory2>

#The output would be the following:
#	1. A list of all the diffs
#	2. A text file which when read (cat), would display the entire diff tree that is coloured for easy interpretation
#	3. A folder with all the actual differences stored under the same hierarchy -> Mutually exclusive files&folders, and common files/folders with only differences inside them (text diff in case of readable files and a hexdump diff in case of non-readable files)


#NOTE: PLEASE PLACE THE SCRIPT AND BOTH DIRECTORIES (OR THE PARENT DIRECTORIES, i.e., don't pass arguments like .. or ../.. as paths) INSIDE THE SAME FOLDER, AND ALSO RUN THE SCRIPT FROM WITHIN THE SAME FOLDER WHERE IT'S LOCATED (<- Have to fix this)

#----------------------------------------------------------------------------------#