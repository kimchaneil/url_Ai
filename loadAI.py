from tensorflow import keras
import tldextract  # 메인 도메인만 추출 (Ex)youtube.com)
import numpy as np
import pickle

with open('./pkl/tokenizer.pkl', 'rb') as tokenizer_file:
    tokenizer = pickle.load(tokenizer_file)

with open('./pkl/tokenizerLabel.pkl', 'rb') as tokenizer_file:
    tokenizerLabel = pickle.load(tokenizer_file)

max_len = 64

def proccess_cnn(input_data, model) :
    reArr = ["1", "2"]

    domain_parts = tldextract.extract(input_data)
    main_domain = domain_parts.domain + "." + domain_parts.suffix

    tokenizer.fit_on_texts(main_domain)
    sequences = tokenizer.texts_to_sequences(main_domain)

    tokenData = []
    for i in sequences:
        tokenData.append(i[0])

    padded_data = tokenData + [0] * (max_len - len(tokenData))


    org_per = model.predict([padded_data])
    predicted_class = np.argmax(org_per)  # 가장 높은 확률을 가진 인덱스
    per = float(org_per[0][predicted_class])*100
    label = tokenizerLabel.word_index
    for i in label:
        if label[i] == predicted_class:
            reArr[0] = i
    if reArr[0] == "non":
        reArr[0] = "safe"

    reArr[1] = round(per, 2)
    return reArr  # [0]에는 결과 [1]에는 확률을 리턴