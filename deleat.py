#!/usr/bin/env python3
def raw_to_human(raw,ip):
    raw = text
    list_1 = []
    list_2 = []
    list_3 = []
    list_4 = []
    list_5 = []
    list_6 = []
    list_7 = []
    list_8 = []
    print()
    count = 0
    for x in ip:
        if x in raw[count]:
            n=len(raw[count][x]['ports'])
            if n != 0:
                file = open(ip[x]+"_port_scan.txt", "w")
                for i in range(len(raw[count][x]['ports'])):
                    list_1.append(raw[count][x]['ports'][i].get('portid','none'))
                    list_2.append(raw[count][x]['ports'][i]['service'].get('name',"none"))
                    list_3.append(raw[count][x]['ports'][i]['service'].get('product',"none"))
                    list_4.append(raw[count][x]['ports'][i]['service'].get('name',"none"))
                    list_5.append(raw[count][x]['ports'][i]['service'].get('version',"none"))
                    list_6.append(raw[count][x]['ports'][i]['service'].get('extrainfo',"none"))
                    list_7.append(raw[count][x]['ports'][i]['service'].get('hostname',"none"))
                    list_8.append(raw[count][x]['ports'][i]['service'].get('conf',"none"))

                space_1 = len(max(list_1, key = len))+4
                space_2 = len(max(list_2, key = len))+4
                space_3 = len(max(list_3, key = len))+4
                space_4 = len(max(list_4, key = len))+4
                space_5 = len(max(list_5, key = len))+4
                space_6 = len(max(list_6, key = len))+10
                space_7 = len(max(list_7, key = len))+8
                space_8 = len(max(list_8, key = len))+10
                print('For IP: ',x)
                print('This computer is running: ',raw[0][x]['osmatch'][0].get('name','none'), 'accuracy: ',raw[0][x]['osmatch'][0].get('accuracy','none'),'\n')
                print("port #".ljust(space_1),"port ID".ljust(space_2),"Serves".ljust(space_3),"product".ljust(space_4),"version".ljust(space_5),"More Info".ljust(space_6),"Host Name".ljust(space_7),"Confidants".ljust(space_8),"\n")
                file.write('For IP: ',x)
                file.write('This computer is running: ',raw[0][x]['osmatch'][0].get('name','none'), 'accuracy: ',raw[0][x]['osmatch'][0].get('accuracy','none'),'\n')
                file.write("port #".ljust(space_1),"port ID".ljust(space_2),"Serves".ljust(space_3),"product".ljust(space_4),"version".ljust(space_5),"More Info".ljust(space_6),"Host Name".ljust(space_7),"Confidants".ljust(space_8),"\n")
                for i in range(len(raw[count][x]['ports'])):
                    print(list_1[i].ljust(space_1),
                        list_2[i].ljust(space_2),
                        list_3[i].ljust(space_3),
                        list_4[i].ljust(space_4),
                        list_5[i].ljust(space_5),
                        list_6[i].ljust(space_6),
                        list_7[i].ljust(space_7),
                        list_8[i].ljust(space_8))
                    file.write(list_1[i].ljust(space_1),
                        list_2[i].ljust(space_2),
                        list_3[i].ljust(space_3),
                        list_4[i].ljust(space_4),
                        list_5[i].ljust(space_5),
                        list_6[i].ljust(space_6),
                        list_7[i].ljust(space_7),
                        list_8[i].ljust(space_8))

                print("\n")
                count+=1
                file.close()
            else:i
                print(x, "has no open ports")
                file.write(x, "has no open ports")
                file.close()
        else:
            print(x, "has no open ports")
            file.write(x, "has no open ports")
            file.close()
    f = open("full_scan", "w")    
    f.write(json.dumps(text, indent=2))
    f.close()
    print("\n \n Results have been saved to this current directory, file name:  ", ip_select[0]+"_port_scan.txt" )        
    return 