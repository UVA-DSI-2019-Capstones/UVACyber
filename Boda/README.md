# DARPA-Cyber-Security

The goal of the project is to utilize Macine Learning methodology to detect zero day malicous attack. We created a data
pipeline to dynamically feed data into ensembled supervised models and achieved 98% accuracy, 1% false positive rate in 
imbalanced data(malicious traffic is 5%)


1. Utilize honeypot, whitelist and blacklist to label the data
2. Sample and balance the data
3. Run four paralle models(Logistic Regression, XGB, ANN, and Random Forest)
4. Ensemble the result
