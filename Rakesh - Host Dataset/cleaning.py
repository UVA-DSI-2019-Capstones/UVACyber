import pandas as pd

file = "/Users/rakeshravi/Documents/Capstone Project/Secondary Dataset - Host Dataset/wls_day-01.txt"

with open(file, "r") as ins:
    array = []
    for line in ins:
        array.append(line)
        
print(len(array))
sample = array[1:10000]

columnlist = ['Time',
'EventID',
'LogHost',
'LogonType',
'LogonTypeDescription',
'UserName',
'DomainName',
'LogonID',
'SubjectUserName',
'SubjectDomainName',
'SubjectLogonID',
'Status',
'Source',
'ServiceName',
'Destination',
'AuthenticationPackage',
'FailureReason',
'ProcessName',
'ProcessID',
'ParentProcessName',
'ParentProcessID']
import json
parsed_df = pd.DataFrame(columns=columnlist)
for x in sample:
    str1 = (''.join(str(e) for e in x)).strip("\n")
    d = json.loads(str1)
    lis = []
    for y in range(0,21):
        try:
            k = d[columnlist[y]]
            lis.append(k)
        except KeyError:
            lis.append(0)
    temp_df = pd.DataFrame([lis], columns = columnlist)
    print(temp_df)
    parsed_df = parsed_df.append(temp_df)

test_df = parsed_df.head(10)
test_df[['EventID']] = test_df[['EventID']].apply(pd.to_numeric)
parsed_df.to_csv(parsed_sample, sep='\t')
parsed_df.to_csv(parsed, sep='\t')
parsed_df.to_csv('parsed_sample.csv', sep='\t')
test_df = parsed_df.head(10)
lookup_df = pd.read_csv('/Users/rakeshravi/Documents/Capstone Project/Secondary Dataset/Host eventID to Des lookup.csv')
test_df[['EventID']] = test_df[['EventID']].apply(pd.to_numeric)
lookup_df[['EventID']] = lookup_df[['EventID']].apply(pd.to_numeric)
parsed_df = pd.read_csv('/Users/rakeshravi/Documents/Capstone Project/Secondary Dataset/parsed_sample.csv')
import pandas as pd

parsed_df = pd.read_csv('/Users/rakeshravi/Documents/Capstone Project/Secondary Dataset/parsed_sample.csv')
parsed_df.to_csv('parsed_sample.csv', sep='\t')
merged_df = pd.merge(test_df, lookup_df, on="EventID")