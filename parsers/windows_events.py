#windows events

import xml.etree.ElementTree as ET

NS = {
    "win": "http://schemas.microsoft.com/win/2004/08/events/event"
}

## extracting data from windows event log xml string ##
def parse_event(root):
    event_id = root.find("win:System/win:EventID", NS).text

    time_element = root.find("win:System/win:TimeCreated", NS)
    timestamp = time_element.get("SystemTime")

    # dictionary comprehension to extract event data
    # into a dictionary with the Name attribute as the key
    # and the text as the value
    event_data = {
        data.get("Name"): data.text
        for data in root.findall("win:EventData/win:Data", NS)
    }

    return {
        "event_id": int(event_id),
        "timestamp": timestamp,
        "username": event_data.get("TargetUserName"),
        "source_ip": event_data.get("IpAddress"),
        "status": event_data.get("Status"),
        "service_name": event_data.get("ServiceName")
    }

## ET.parse(file_path) reads the XML file and returns the XML tree as an object
## tree.getroot() retrieves outer <Events> element, which contains all event elements
## we then pass each event into a dictionary using a for loop
## root.findall() finds each individual <Event>
## we pass each <Event> into the parse_event function to extract data
## we extract our data into a list of dictionaries, we then return the lists

def parse_file(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    events = []

    for event in root.findall("win:Event", NS):
        parsed_event = parse_event(event)
        events.append(parsed_event)
    return events

if __name__ == "__main__":
    from pathlib import Path

    file_path = (
        Path(__file__).resolve().parent.parent
        / "sample_data"
        / "sample_events.xml"
    )

    print("File path:", file_path)
    print("File exists:", file_path.exists())
    print("File size:", file_path.stat().st_size, "bytes")
    
    events = parse_file(file_path)

    for event in events:
        print(event)