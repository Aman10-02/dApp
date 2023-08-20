import hashlib
# from pymongo import MongoClient
def calculate_hash(file_path, hash_algorithm='sha256'):
    hash_object = hashlib.new(hash_algorithm)

    with open(file_path, 'rb') as file:
        chunk = file.read(4096)  
        while chunk:
            hash_object.update(chunk)
            chunk = file.read(4096)

    return hash_object.hexdigest()

pem_file_path = './public_key.pem'
hash_algorithm = 'sha256'  

hash_string = calculate_hash(pem_file_path, hash_algorithm)
print(hash_string)



# uri = 'mongodb+srv://user:Shashank@cluster0.kyus6u4.mongodb.net/?retryWrites=true&w=majority'

# client = MongoClient(uri)

# db = client['your_database_name']

# collection = db['your_collection_name']

# name = 'John'
# value = hash_string
# document = {"name": name, "value": value}
# insert_result = collection.insert_one(document)

# print(f"Inserted document ID: {insert_result.inserted_id}")

# documents = collection.find()
# for doc in documents:
#     print(doc)

# client.close()
