import csv
import pandas as pd
from .models import CustomDutyFile
from .serializers import CustomDutyUploadSerializer


# Define the required column indexes and their corresponding field names

def process_csv(file):
    try:
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
                return {"error": "Invalid data in CSV", "details": serializer.errors}

        CustomDutyFile.objects.bulk_create(custom_duties)

        return {"success": "CSV file processed successfully."}
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
        return {"success": "Excel file processed successfully."}

    except Exception as e:
        return {
            "error": "An error occurred while processing the Excel file.",
            "details": str(e),
        }
