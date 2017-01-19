import re
import collections
import operator

#Create empty arrays to hold the hash values
allHashes = []
allHashesWithDates = []

#Open the log file
file = open('sfc.exe.log','r')

#Gather information on the hashes
for line in file:
    if "file hash" in line:
        #Find the hash of the file scanned
        hashStart = line.find('file hash: ')
        hashEnd = line.find(',',hashStart)
        theHash = line[hashStart+11:hashEnd]
        
        #Find the timestamp of the scan
        firstprocesshLoc = line.find(')')
        bracketAfterprocessh = line.find('[',firstprocesshLoc)
        lineTime = line[firstprocesshLoc+2:bracketAfterprocessh-1]
        
        #Find the name of the file
        fileNameStart = line.find(': ',hashEnd)
        fileNameEnd = line.find(']',fileNameStart)
        fileName = line[fileNameStart+1:fileNameEnd]
        
        #Find the process process hash
        processHashLoc = line.find('process hash: ')
        processHashEndLoc = line.find(',',processHashLoc)
        processHash = line[processHashLoc+14:processHashEndLoc]
        
        #Find the name of the process
        processNameStart = line.find(': ',processHashEndLoc)
        processNameEnd = line.find(']',processNameStart)
        processName = line[processNameStart+1:processNameEnd]
        
        #Find the PID of this instance
        processIDStart = line.find('[')
        processIDEnd = line.find(']')
        processID = line[processIDStart:processIDEnd]
        
        #Find information from line that contains the full path
        for line in file:
            if (processID and fileName) in line:
                
                #Find the full File Path
                filePathStart = line.find('HandleCreation')
                filePathEnd = line.find(fileName)
                filePath = line[filePathStart:filePathEnd]
                
                #Find the full Parent Path
                fileParentStart = line.find(fileName)
                fileParentEnd = line.find(processName)
                fileParent = line[fileParentStart:fileParentEnd]
                
        #Put hashes into the arrays
        allHashes.append(theHash)
        allHashesWithDates.append((theHash, fileName, filePath, processHash, processName, lineTime))

#Count how many times a hash was scanned      
counter = collections.Counter(allHashes)

#Print headers for .csv
print "Hash, File Name, File Path, Process Hash, Process Name, Timestamp, Scan Count"

#Print data
for i in allHashesWithDates:
    print i[0]+ ", " + i[1] + ", " + i[2] + "," + i[3] + "," + i[4] + "," + i[5] + "," + ''+str(counter[i[0]])+''

