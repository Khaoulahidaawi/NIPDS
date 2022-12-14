# NIPDS
of implementing a Packet-Based Intelligent Network phishing Intrusion Detection system. The idea of the design is to use machine learning to classify Network packets to benign and phishing in real-time flow (for both http/https protocol) based on DNS records and domain name features. It operates by using a pre-programmed list of known phishing threat features and their indicators of compromise (IOCs). As a signature based INPDS it will monitor the packets traversing the network, it compares these packets to the database of known IOCs or attack signatures to flag any suspicious behavior. 

In this research, we proposed an applicable phishing domain classification detection system based on lexical and third-party features acquired by deep inspection of DNS traffic. The proposed detection system achieves a somewhat promising preliminary results on several machine learning techniques. We also have shown that third-party features are the most important category of features in the classification process with a total 58% information gain among the top 13 features. We have worked on implementing a passive python network sniffer that capture live flow traffic and save it to a PCAP file so we can extract 22 features from 500,000 benign and 5,011 malicious DNS responses captured from over seven million DNS packets. In the future, we are planning to enrich our feature set by adding more state full /stateless features to add up to 35 features as well as orienting this INPDS system towards HTTPS protocol.


View  Repport for more details on the architecture and desgin : 

KHAOULA HIDAWI. (2022). Network Packet level –based Intelligent Phishing Intrusion Detection System. Zenodo. https://doi.org/10.5281/zenodo.6950088
