import re
import collections
import operator

#new comment playing with pulls

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

        #Put hashes into the arrays
        allHashes.append(theHash)
        allHashesWithDates.append((theHash, fileName, processHash, processName, lineTime))

#Count how many times a hash was scanned      
counter = collections.Counter(allHashes)

#Print headers for .csv
print "Hash, File Name, Process Hash, Process Name, Timestamp, Scan Count"

#Print data
for i in allHashesWithDates:
    print i[0]+ ", " + i[1] + ", " + i[2] + "," + i[3] + "," + i[4] + "," + ''+str(counter[i[0]])+''

