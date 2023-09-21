import pandas as pd
import numpy as np
from tensorflow import keras
from keras.models import Model
from keras.layers import Embedding, Dense, Dropout, LSTM, Input, BatchNormalization
from sklearn.model_selection import train_test_split
from keras.regularizers import l2
from keras.utils import to_categorical
from keras.layers import  Dense, Dropout


data = pd.read_csv('preprocessing_1.csv')
X = data['host'].values
y = data['subclass'].values

X_reshape = []
for data in X:
    X_reshape.append(eval(data))  # 각각의 데이터를 문자열로 가져오기 때문에 다시 배열로 저장하기 위함, 시간 오래걸림
y_int = []
i = 0

# 라벨 데이터가 문자열이라서 인코딩 되지 않기 때문에 [i] 형태의 데이터를 숫자만 가지고 옴
while i < len(y):
    y_int.append(y[i][1])
    i += 1
y_encoded = to_categorical(y_int)

vocab_size = 39  # 데이터의 문자 종류가 38번까지 있고 여기서 임베딩 토큰 때문에 1이 더해진 39가 크기가 됨
embedding_dim = 32  # 차원 크기
max_len = 64  # 패딩 길이
num_classes = 9  # 라벨의 종류 + 1

# 훈련 데이터와 검증 데이터(검증 데이터 20%)
X_train, X_test, y_train, y_test = train_test_split(X_reshape, y_encoded, test_size=0.2, random_state=42)
X_train = np.array(X_train)
X_test = np.array(X_test)

# input layer
input_seq = Input(shape=(max_len,))
# 임베딩 레이어
embedding = Embedding(input_dim=vocab_size, output_dim=embedding_dim, input_length=max_len,
                      embeddings_regularizer=l2(0.15), input_shape=(max_len, 1))(input_seq)

lstm_layer = LSTM(units=128, return_sequences=True)(embedding)  # 논문에서 lstm 출력 차원을 128, return_sequences를 true로 지정

attention_scores = keras.layers.Attention()([lstm_layer, lstm_layer])  # Attention Weight layer

softmax_scores = keras.layers.Softmax(axis=1)(attention_scores)  # Attention score를 softmax로 정규화 하여 확률값으로 변환

attended_output = keras.layers.Dot(axes=(1, 1))([softmax_scores, lstm_layer])  # Weight Sum layer

output_layer = Dense(128, activation='relu')(attended_output)  # Fully Connected Layer, 논문에서 activation 함수를 Relu로 지정
normalized = BatchNormalization()(output_layer)  # 배치 정규화
dropout = Dropout(0.5)(normalized)  # Dropout

model = Model(inputs=input_seq, outputs=dropout)
model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
model.summary()

model.fit(X_train, y_train, batch_size=64, epochs=10, validation_data=(X_test, y_test))  # 모델 학습

evaluation = model.evaluate(X_test, y_test)

print(f"손실: {evaluation[0]}")
print(f"정확도: {evaluation[1]}")