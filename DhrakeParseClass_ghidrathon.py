from ghidra.program.model.data import StructureDataType, IntegerDataType, PointerDataType, CategoryPath, DataType, DataTypeConflictHandler, FunctionDefinitionDataType
from ghidra.program.model.symbol import SourceType

def putType(dt, h):
    return getCurrentProgram().getDataTypeManager().addDataType(dt, h)

def addFnType(fn):
    ft = FunctionDefinitionDataType(fn, False);
    return putType(ft, DataTypeConflictHandler.KEEP_HANDLER)

def ReadPascalStringScript():
    address = currentAddress()
    if address is None:
        return
    try:
        length = getByte(address)
    except Exception as e:
        print("Error reading length byte: " + str(e))
        return
    if (length == 0):
        print("Found an empty Pascal string at " + str(address))
        return
    string_bytes = getBytes(address.add(1), length)
    
    try:
        pascal_string = bytearray(string_bytes).decode('ascii')
        return pascal_string
    except Exception as e:
        self.print("Error decoding string bytes: " + str(e))
    return

def main():
    print("Parsing all Delphi classes")
    st=getCurrentProgram().getSymbolTable()
    for s in st.getAllSymbols(True):
        sName=s.getName()
        sAddr=s.getAddress()
        if "VMT" in sName:
            print("Name: {}\n\tAddr: {}".format(sName, sAddr))
            setCurrentLocation(sAddr)
            className=""
            try:
                setCurrentLocation(toAddr(getInt(currentAddress().add(32))))
                className=ReadPascalStringScript()
                setCurrentLocation(sAddr)
                if (className==None):
                    continue
            except:
                continue
            #
            if className.upper().startswith("T") or className.upper().startswith("E"):
                parentNamespace = currentProgram().getGlobalNamespace()
                try:
                    classNamespace = currentProgram().getSymbolTable().convertNamespaceToClass(currentProgram().getSymbolTable()\
                        .getOrCreateNameSpace(currentProgram().getGlobalNamespace(), className, SourceType.USER_DEFINED))
                except DuplicateNameException:
                    print(f"Class '{className}' already exists.")

                #
                base = StructureDataType(CategoryPath("/"), className, 0, currentProgram().getDataTypeManager())
                vtbl = StructureDataType(CategoryPath("/"), className + "VT", 0, currentProgram().getDataTypeManager())
                vt = getInt(currentAddress())
                #
                if (classNamespace != None):
                    print("\tParsing class {}".format(className))
                    hiAddr = vt + 4 * 100
                    #print("\tVT: 0x{}\thiAddr: 0x{}".format(toAddr(vt), toAddr(hiAddr)))
                    for currAddr in range(vt,hiAddr, 4):
                        try:
                            offset = getInt(toAddr(currAddr))
                            name = None
                            entryPoint = toAddr(offset)
                            function = getFunctionAt(entryPoint)
                            #print("\tOffset: 0x{}\n\tentryPoint: 0x{}\n\tFunction: {}".format(offset, entryPoint, function))
                            if (function == None):
                                name = getSymbolAt(entryPoint).toString()
                                if (name==None):
                                    name = "FUN_{}".format(offset)
                                print("\tdefining function at 0x{}, name {}".format(offset, name))
                                function=createFunction(entryPoint, name)
                            if (function==None):
                                break
                            function.setParentNamespace(classNamespace)
                            name = function.getName()
                            print("\tadding function: {}::{}".format(className, name))
                            vtbl.add(addFnType(function), 4, name, "");
                        except Exception as e:
                            #print(f"An unexpected error occurred: {e}")
                            continue

                    base.add(getCurrentProgram().getDataTypeManager().getPointer(putType(vtbl, DataTypeConflictHandler.REPLACE_HANDLER)), "vt", "Virtual Function Table")
                    putType(base, DataTypeConflictHandler.REPLACE_HANDLER)

if __name__ == '__main__':
    main()
