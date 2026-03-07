import xmltodict
import pandas as pd

with open("sysmon_logs.xml","r",encoding="utf-8") as f:
    xml_data=f.read()

data_dict=xmltodict.parse(xml_data)
events=data_dict["Events"]["Event"]

if isinstance(events,dict):
    events=[events]

process_events=[]

for event in events:
    if str(event["System"]["EventID"])=="1":
        event_data=event["EventData"]["Data"]
        if isinstance(event_data,dict):
            event_data=[event_data]
        data_fields={}
        for item in event_data:
            field_name=item.get("@Name")
            field_value=item.get("#text","")
            data_fields[field_name]=field_value
        process_events.append({
            "Time":event["System"]["TimeCreated"]["@SystemTime"],
            "Image":data_fields.get("Image",""),
            "CommandLine":data_fields.get("CommandLine",""),
            "ParentImage":data_fields.get("ParentImage","")
        })

df=pd.DataFrame(process_events)

df["Risk"]="Low"
df.loc[df["CommandLine"].str.contains("-enc",case=False,na=False),"Risk"]="High"
df.loc[df["Image"].str.contains("AppData|Temp",case=False,na=False),"Risk"]="Medium"

print("\nHigh Risk Events:\n")
print(df[df["Risk"]=="High"])

print("\nMedium Risk Events:\n")
print(df[df["Risk"]=="Medium"])

df.to_csv("analysis_results.csv",index=False)