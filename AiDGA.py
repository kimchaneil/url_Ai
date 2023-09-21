import pandas as pd
import numpy as np
from keras.models import Model
from keras.layers import Embedding, Dense, Dropout, Conv1D, GlobalMaxPooling1D, Concatenate, Input, BatchNormalization
from sklearn.model_selection import train_test_split
from keras.regularizers import l2
from keras.utils import to_categorical
from keras.activations import elu

data = pd.read_csv('./dataset/preprocessing.csv')
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
# 논문에서 32차원으로 임베딩을 하였고 input_length는 패딩한 길이
# 논문에서 과적합(오퍼피팅)을 방지하기 위하여 Dropout(0.5)과 L2 regularization(정규화) 진행(Dropout은 Hidden layer에서 적용)

# 컨볼루션 레이어, 풀링 레이어
conv1 = Conv1D(filters=256, kernel_size=2, strides=1, padding='same', activation='relu')(embedding)
pooling1 = GlobalMaxPooling1D()(conv1)

conv2 = Conv1D(filters=256, kernel_size=3, strides=1, padding='same', activation='relu')(embedding)
pooling2 = GlobalMaxPooling1D()(conv2)

conv3 = Conv1D(filters=256, kernel_size=4, strides=1, padding='same', activation='relu')(embedding)
pooling3 = GlobalMaxPooling1D()(conv3)

conv4 = Conv1D(filters=256, kernel_size=5, strides=1, padding='same', activation='relu')(embedding)
pooling4 = GlobalMaxPooling1D()(conv4)

# 합치고 연결
merged = Concatenate()([pooling1, pooling2, pooling3, pooling4])

# 활성 함수 elu 사용
dense_1 = Dense(units=128, activation=elu)(merged)  # Fully Connected Layer
normalized_1 = BatchNormalization()(dense_1)  # 배치 정규화
dropout_1 = Dropout(0.5)(normalized_1)  # Dropout

# Hidden layer2
dense_2 = Dense(units=128, activation=elu)(dropout_1)  # Fully Connected Layer
normalized_2 = BatchNormalization()(dense_2)  # 배치 정규화
dropout_2 = Dropout(0.5)(normalized_2)  # Dropout

# Hidden layer3
dense_3 = Dense(units=128, activation=elu)(dropout_2)  # Fully Connected Layer
normalized_3 = BatchNormalization()(dense_3)  # 배치 정규화
dropout_3 = Dropout(0.5)(normalized_3)  # Dropout

output = Dense(num_classes, activation='softmax')(dropout_3)

model = Model(inputs=input_seq, outputs=output)
model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
model.summary()

model.fit(X_train, y_train, batch_size=64, epochs=10, validation_data=(X_test, y_test))  # 모델 학습

evaluation = model.evaluate(X_test, y_test)

print(f"손실: {evaluation[0]}")
print(f"정확도: {evaluation[1]}")

model.save("D:/CNN/CNN4.h5")