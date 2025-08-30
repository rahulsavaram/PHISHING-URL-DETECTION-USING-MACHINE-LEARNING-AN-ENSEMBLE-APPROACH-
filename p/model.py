#importing required libraries

import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
#%matplotlib inline
import seaborn as sns
from sklearn import metrics 
import warnings
warnings.filterwarnings('ignore')



data = pd.read_csv(r"C:\Users\DELL\Documents\4th\p\phishing.csv")


data = data.drop(['Index'],axis = 1)


X = data.drop(["class"],axis =1)
y = data["class"]


from sklearn.model_selection import train_test_split

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.2, random_state = 42)
# X_train.shape, y_train.shape, X_test.shape, y_test.shape



from sklearn.ensemble import GradientBoostingClassifier

# instantiate the model
gbc = GradientBoostingClassifier(n_estimators=100,max_depth=4,learning_rate=0.7)

# fit the model 
gbc.fit(X_train,y_train)

import pickle
os.makedirs("pickle", exist_ok=True)

# Save the model
with open("pickle/model-1.pkl", "wb") as f:
    pickle.dump(gbc, f)

# dump information to that file
#pickle.dump(gbc, open('pickle/model-1.pkl', 'wb'))