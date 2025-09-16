import pdqhash
import cv2

image = cv2.imread(os.path.join('src', 'test_data', "emma.jpeg"))
image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
hash_vector, quality = pdqhash.compute(image)
print(hash_vector)
print(quality)
