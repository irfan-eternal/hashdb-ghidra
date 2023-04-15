# Rename Hashed API's using Ghidra
#@irfan_eternal 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


from ghidra.program.model.data import Enum
from ghidra.program.model.data import EnumDataType
from ghidra.program.model import listing
from ghidra.program.model.symbol import SourceType
import csv

a = [];
hashtable = [];
hashvalues = [];

a = findBytes(currentProgram.getMinAddress(), '\x93\x01\00\x01', 3000);
for i in a:
    function_name = getFunctionContaining(i);
    address = str(i);
    address  = int(address, 16);
    for j in range(address, address + 20, 2):
         instruction = getInstructionBefore(toAddr(hex(j)))
         instruction = str(instruction)
         result = instruction.find("CMP")
         if (result != -1) :
             res = instruction.find("0x")
             if (res != -1) :
                 addressofCompare = j;
                 hash = instruction.split(",")[1].lstrip();
                 hashtable.append([function_name, hash, addressofCompare]);
                 break;
             
with open('C:\\Users\\IEUser\\Downloads\\bpin.csv') as csvfile:
     reader = csv.DictReader(csvfile)
     for row in reader:
         hashvalues.append([row['Name'], row['Value']])

for x in hashtable:
        for y in hashvalues:
                if (x[1] == y[1]):
                    func = x[0];
                    func.setName("resolve"+y[0], SourceType.ANALYSIS);
                    setEOLComment((toAddr(str(hex(x[2])))), y[0]);
                    print(y[0]+ " resolved");
                    break;  
