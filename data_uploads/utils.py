import csv
import pandas as pd
from .models import CustomDutyFile
from .serializers import CustomDutyUploadSerializer
import hashlib
import xml.etree.ElementTree as ET
import json


# Define the required column indexes and their corresponding field names


def process_csv(file):
    try:
        file.seek(0)
        file_data = file.read().decode("utf-8")
        csv_reader = csv.DictReader(file_data.splitlines())
        custom_duties = []

        for row in csv_reader:
            row = {k: v.strip() if v else "" for k, v in row.items()}
            serializer = CustomDutyUploadSerializer(data=row)
            if serializer.is_valid():
                custom_duty = CustomDutyFile(**serializer.validated_data)
                custom_duties.append(custom_duty)
            else:
                print(serializer.errors)
                return {"error": "Invalid data in CSV", "details": serializer.errors}

        CustomDutyFile.objects.bulk_create(custom_duties)

        return {"message": "CSV file processed successfully."}
    except Exception as e:
        return {
            "error": "An error occurred while processing the CSV file.",
            "details": str(e),
        }


def process_excel(file):
    try:
        # Use pandas to read the Excel file
        df = pd.read_excel(file)

        # Convert the DataFrame to a list of dictionaries
        custom_data = df.to_dict(orient="records")
        custom_duties = []

        for row in custom_data:
            row = {k: v.strip() if v else "" for k, v in row.items()}
            serializer = CustomDutyUploadSerializer(data=row)
            if serializer.is_valid():
                custom_duty = CustomDutyFile(**serializer.validated_data)
                custom_duties.append(custom_duty)
            else:
                return {"error": "Invalid data in Excel", "details": serializer.errors}

        CustomDutyFile.objects.bulk_create(custom_duties)
        return {"message": "Excel file processed successfully."}

    except Exception as e:
        return {
            "error": "An error occurred while processing the Excel file.",
            "details": str(e),
        }


# Process duplicates
def is_duplicate(file):
    """
    Checks for duplicate files by comparing file names or content.
    """
    # check by file name
    existing_files = CustomDutyFile.objects.filter(name=file.name)

    # check by file content(using hash)
    file_hash = hashlib.md5(file.read()).hexdigest()
    for existing_file in existing_files:
        existing_file_hash = hashlib.md5(existing_file.file.read()).hexdigest()
        if file_hash == existing_file_hash:
            return True
    return False


# Process JSON files
def process_json(file):
    """
    Process JSON files and return a response dictionary.
    """
    try:
        data = json.load(file)
        # Implement the logic to process the JSON data
        return {"message": "JSON file processed successfully"}
    except Exception as e:
        return {"error": f"Failed to process JSON file: {str(e)}"}


# process XML file
def process_xml(file):
    """
    Process XML files and return a response dictionary.
    """
    try:

        tree = ET.parse(file)
        root = tree.getroot()
        # Implement the logic to process the XML data
        return {"message": "XML file processed successfully"}
    except Exception as e:
        return {"error": f"Failed to process XML file: {str(e)}"}
