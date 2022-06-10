import os
import glob
import toml
import pymongo
import requests
import json

MONGODB = os.getenv("MONGODB")

if MONGODB is None:
    raise Exception("MONGODB environment variable not set")

client = pymongo.MongoClient(MONGODB)
db = client.rsad

rust_count = 0
crates_count = 0

files = glob.glob("rust/**/*.md")
for file in files:
    with open(file, 'r') as f:
        project = file.split('/')[1]
        id = file.split('/')[2].split('.')[0]
        print("Processing {} - {}".format(project, id))
        try:
            contents = f.readlines()
            toml_contents = ""
            for line in contents:
                if line == "```toml\n":
                    continue
                if line == "```\n":
                    break
                toml_contents += line
            raw_data = toml.loads(toml_contents)
            data = {}
            if "advisory" in raw_data:
                for (key, value) in raw_data["advisory"].items():
                    data["advisory_{}".format(key)] = value
            if "affected" in raw_data:
                for (key, value) in raw_data["affected"].items():
                    data["affected_{}".format(key)] = value
            if "versions" in raw_data:
                for (key, value) in raw_data["versions"].items():
                    data["versions_{}".format(key)] = value
            if db.rust.find_one({"advisory_id": id}) is None:
                db.rust.insert_one(data)
            rust_count += 1
        except Exception as e:
            print("Failed to process {}: {}".format(id, e.with_traceback()))
            continue

files = glob.glob("crates/**/*.md")
for file in files:
    with open(file, 'r') as f:
        crate = file.split('/')[1]
        id = file.split('/')[2].split('.')[0]
        print("Processing {} - {}".format(crate, id))
        try:
            crates_req = requests.get("https://crates.io/api/v1/crates/{}".format(crate))
            crates_data = json.loads(crates_req.text)
            crates_categories = []
            for item in crates_data["categories"]:
                crates_categories.append(item["category"])
            contents = f.readlines()
            toml_contents = ""
            for line in contents:
                if line == "```toml\n":
                    continue
                if line == "```\n":
                    break
                toml_contents += line
            raw_data = toml.loads(toml_contents)
            data = {}
            if "advisory" in raw_data:
                for (key, value) in raw_data["advisory"].items():
                    data["advisory_{}".format(key)] = value
            if "affected" in raw_data:
                for (key, value) in raw_data["affected"].items():
                    data["affected_{}".format(key)] = value
            if "versions" in raw_data:
                for (key, value) in raw_data["versions"].items():
                    data["versions_{}".format(key)] = value
            data["crates_categories"] = crates_categories
            if db.crates.find_one({"advisory_id": id}) is None:
                db.crates.insert_one(data)
            crates_count += 1
        except Exception as e:
            print("Failed to process {}: {}".format(id, e.with_traceback()))
            continue

print("Processed {} Rust advisories and {} crates advisories".format(rust_count, crates_count))
