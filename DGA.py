# -*- coding: utf-8 -*-

import csv
from keras.preprocessing.text import Tokenizer
import pickle

dga = []
url = []
label = []

with open('./dataset/dga_data_no_name.csv', 'r') as f:
    data = csv.reader(f)
    for line in data:
        dga.append([line[0], line[2], line[3]])

# texts = [' '.join(line) for line in seqs]
# 2차원 배열로 저장되어서 1차원으로 바꿈
# tokenizer는 2차원 배열을 지원하지 않아서 1차원 배열로 바꾸는 작업이 필요함
# 원래는 dga여부와 URL을 같이 받아왔지만 2차원 배열을 지원하지 않아서 수정
for urldata in dga:
    url.append(urldata[1])
    label.append(urldata[2])

# URL 데이터 토큰화
tokenizer = Tokenizer(char_level=True)  # 문자 기준 토큰화
tokenizer.fit_on_texts(url)
sequences = tokenizer.texts_to_sequences(url)

# from keras.preprocessing.sequence import pad_sequences
# 위 라이브러리에 제로패딩 함수가 있지만 임포트 되지 않아서 직접 수행

max_len = max(len(item) for item in sequences)

padded_sequences = []
for seq in sequences:
    padded_seq = seq + [0] * (max_len - len(seq))
    padded_sequences.append(padded_seq)

i = 0
while i < len(label):
    if label[i] == "legit" or label[i] == "alexa":
        label[i] = 'non'
    i += 1

# Label 데이터 토큰화
tokenizerLabel = Tokenizer()
tokenizerLabel.fit_on_texts(label)
label_sequences = tokenizerLabel.texts_to_sequences(label)

# dga여부와 전처리된 URL로 배열 다시 구성
for i in range(len(dga)):
    dga[i][1] = padded_sequences[i]
    dga[i][2] = label_sequences[i]

# csv파일로 저장
rows = [(dga[i][0], dga[i][1], dga[i][2]) for i in range(len(dga))]
with open('./dataset/preprocessing.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerows(rows)