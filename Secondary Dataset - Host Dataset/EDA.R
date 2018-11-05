setwd("/Users/rakeshravi/Documents/Capstone Project/Secondary Dataset/")
parsed <-  read.csv("parsed_sample.csv", stringsAsFactors = FALSE,  sep = "\t")
lookup <- read.csv("Host eventID to Des lookup.csv", stringsAsFactors = FALSE)
parsed$EventID <-  as.numeric(parsed$EventID)
merged <-  merge(parsed, lookup, by = "EventID")
summary(merged)
test <-  merged

#missing values 
test[test == 0] <- NA
emptyvalues <- as.data.frame(sapply(merged, function(x) sum(is.na(x))*100/9999))
write.csv(emptyvalues, file = "emptyvalues.csv")
filtered <-  merged[merged$LogonType == 5,]

k <-  as.data.frame(table(merged$Category))
write.csv(merged, file = "merged.csv")
