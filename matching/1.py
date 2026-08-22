import os
import csv
import pandas as pd
from scapy.all import rdpcap, IP
from scapy.layers.inet import TCP
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from pytz import timezone

# 设备名称集中管理
DEVICE_NAMES = {
    'camera': 'Xiaomi intelligent camera on/off',
    'xiaomi_bulb_off': 'Mijia LED bulb off',
    'xiaomi_bulb_on': 'Mijia LED bulb on',
    'aqara_bulb': 'Aqara LED bulb on/off',
    'xiaomi_plug': 'Xiaomi intellectual socket on/off',
    'door': 'Aqara door/window sensor on and off'
}

# 读取数据集
camera_on_off_data = pd.read_csv('XiaomiCamera-ON-OFF.csv')
#camera_off_data = pd.read_csv('XiaomiCamera-OFF.csv')
xiaomi_bulb_off_data = pd.read_csv('xiaomi-bulb-OFF.csv')
xiaomi_bulb_on_data = pd.read_csv('xiaomi-bulb-ON.csv')
aqara_bulb_on_off_data = pd.read_csv('aqara-bulb-ON-OFF.csv')
xiaomi_plug_on_off_data = pd.read_csv('xiaomi-plug-ON-OFF.csv')
aqara_door_and_window_sensor_on_off_data = pd.read_csv('door-ON-OFF.csv')

# 添加标签列
camera_on_off_data['Label'] = DEVICE_NAMES['camera']
#camera_off_data['Label'] = DEVICE_NAMES['camera_off']
xiaomi_bulb_off_data['Label'] = DEVICE_NAMES['xiaomi_bulb_off']
xiaomi_bulb_on_data['Label'] = DEVICE_NAMES['xiaomi_bulb_on']
aqara_bulb_on_off_data['Label'] = DEVICE_NAMES['aqara_bulb']
xiaomi_plug_on_off_data['Label'] = DEVICE_NAMES['xiaomi_plug']
aqara_door_and_window_sensor_on_off_data['Label'] = DEVICE_NAMES['door']

# 合并数据集
data_4 = pd.concat([camera_on_off_data, xiaomi_bulb_off_data, xiaomi_bulb_on_data, xiaomi_plug_on_off_data, aqara_door_and_window_sensor_on_off_data], ignore_index=True)
data_2 = pd.concat([aqara_bulb_on_off_data], ignore_index=True)

# 编码方向和标签（为两个数据集创建独立的编码器）
label_encoder_direction_4 = LabelEncoder()
label_encoder_label_4 = LabelEncoder()
label_encoder_direction_2 = LabelEncoder()
label_encoder_label_2 = LabelEncoder()

# 处理 data_4 的 Direction 列和 Label
for i in range(1, 5):
    direction_col = f'Direction{i}'
    if direction_col in data_4.columns:
        data_4[direction_col] = label_encoder_direction_4.fit_transform(data_4[direction_col])
data_4['Label'] = label_encoder_label_4.fit_transform(data_4['Label'])

# 处理 data_2 的 Direction 列和 Label
for i in range(1, 3):
    direction_col = f'Direction{i}'
    if direction_col in data_2.columns:
        data_2[direction_col] = label_encoder_direction_2.fit_transform(data_2[direction_col])
data_2['Label'] = label_encoder_label_2.fit_transform(data_2['Label'])

# 定义特征列
feature_columns_4 = [f'DateSize{i}' for i in range(1, 5)] + [f'Direction{i}' for i in range(1, 5)]
feature_columns_2 = [f'DateSize{i}' for i in range(1, 3)] + [f'Direction{i}' for i in range(1, 3)]

# 确保数据没有缺失值
data_4 = data_4.dropna(subset=feature_columns_4)
data_2 = data_2.dropna(subset=feature_columns_2)

# 准备训练数据
X_4 = data_4[feature_columns_4]
y_4 = data_4['Label']
X_2 = data_2[feature_columns_2]
y_2 = data_2['Label']

# 划分训练集和测试集
X_train_4, X_test_4, y_train_4, y_test_4 = train_test_split(X_4, y_4, test_size=0.3, random_state=42)
X_train_2, X_test_2, y_train_2, y_test_2 = train_test_split(X_2, y_2, test_size=0.3, random_state=42)

# 训练随机森林模型
model_4 = RandomForestClassifier(n_estimators=100, random_state=42)
model_4.fit(X_train_4, y_train_4)

model_2 = RandomForestClassifier(n_estimators=100, random_state=42)
model_2.fit(X_train_2, y_train_2)

# 预测
y_pred_4 = model_4.predict(X_test_4)
y_pred_2 = model_2.predict(X_test_2)

# 分类报告
report_4 = classification_report(
    y_test_4, y_pred_4,
    labels=label_encoder_label_4.transform(label_encoder_label_4.classes_),
    target_names=label_encoder_label_4.classes_,
    zero_division=0
)
report_2 = classification_report(
    y_test_2, y_pred_2,
    labels=label_encoder_label_2.transform(label_encoder_label_2.classes_),
    target_names=label_encoder_label_2.classes_,
    zero_division=0
)
#print("Model 4 (Four Size Sequences) Report:\n", report_4)
#print("Model 2 (Two Size Sequences) Report:\n", report_2)

# 保存模型和编码器
joblib.dump(model_4, 'random_forest_model_4.pkl')
joblib.dump(model_2, 'random_forest_model_2.pkl')
joblib.dump(label_encoder_direction_4, 'label_encoder_direction_4.pkl')
joblib.dump(label_encoder_label_4, 'label_encoder_label_4.pkl')
joblib.dump(label_encoder_direction_2, 'label_encoder_direction_2.pkl')
joblib.dump(label_encoder_label_2, 'label_encoder_label_2.pkl')

# 从PCAP文件中提取特征
def extract_features_from_pcap(pcap_file, data_4, data_2):
    packets = rdpcap(pcap_file)
    features_4 = []
    features_2 = []

    # 提取签名中出现的数据包大小对
    size_quads = set(zip(data_4['DateSize1'], data_4['DateSize2'], data_4['DateSize3'], data_4['DateSize4'],
                         data_4['Direction1'], data_4['Direction2'], data_4['Direction3'], data_4['Direction4']))
    #print(size_quads)
    size_pairs = set(zip(data_2['DateSize1'], data_2['DateSize2'], data_2['Direction1'], data_2['Direction2']))

    # 创建一个字典存储数据包信息，并按时间排序
    packet_dict = {}
    for packet in packets:
        # 只处理TCP协议的数据包
        if IP in packet and TCP in packet:
            size = len(packet)
            timestamp = float(packet.time)

            if size not in packet_dict:
                packet_dict[size] = []
            packet_dict[size].append(timestamp)
    # 对每个size对应的时间戳列表进行排序
    for size in packet_dict:
        packet_dict[size].sort()  # 按时间升序排列

    # 找到时间最近的匹配数据包四元组
    matched_times_4 = set()
    for (size1, size2, size3, size4, direction1, direction2, direction3, direction4) in size_quads:
        if size1 in packet_dict and size2 in packet_dict and size3 in packet_dict and size4 in packet_dict:
            for time1 in sorted(packet_dict[size1]):
                closest_time2_candidates = [t for t in packet_dict[size2] if t > time1]
                if not closest_time2_candidates:
                    continue
                closest_time2 = min(closest_time2_candidates)

                closest_time3_candidates = [t for t in packet_dict[size3] if t > closest_time2]
                if not closest_time3_candidates:
                    continue
                closest_time3 = min(closest_time3_candidates)

                closest_time4_candidates = [t for t in packet_dict[size4] if t > closest_time3]
                if not closest_time4_candidates:
                    continue
                closest_time4 = min(closest_time4_candidates)

                # 设置总时间差的条件
                if size1 == 223 and size2 == 143 and size3 == 223 and size4 == 143:
                    time_difference_limit = 6  # 6 秒
                else:
                    time_difference_limit = 2  # 默认 2 秒

                if abs(time1 - closest_time4) < time_difference_limit:
                    if time1 not in matched_times_4 and closest_time2 not in matched_times_4 and closest_time3 not in matched_times_4 and closest_time4 not in matched_times_4:
                        features_4.append([time1, size1, size2, size3, size4])
                        matched_times_4.add(time1)
                        matched_times_4.add(closest_time2)
                        matched_times_4.add(closest_time3)
                        matched_times_4.add(closest_time4)

    matched_times_2 = set()
    #for (size1, size2, direction1, direction2) in size_pairs:
    #    if size1 in packet_dict and size2 in packet_dict:
    #        for time1 in sorted(packet_dict[size1]):
    #            # 找到所有时间在time1之后的size2数据包
    #            closest_time2_candidates = [t for t in packet_dict[size2] if t > time1]
    #            if not closest_time2_candidates:
    #                continue
    #            closest_time2 = min(closest_time2_candidates)

    #            if time1 not in matched_times_2 and closest_time2 not in matched_times_2:
    #                features_2.append([time1, size1, size2])
    #                matched_times_2.add(time1)
    #                matched_times_2.add(closest_time2)

    return features_4, features_2

# 从PCAP文件中提取特征
pcap_file = '0731_five(2.3).pcap'
pcap_features_4, pcap_features_2 = extract_features_from_pcap(pcap_file, data_4, data_2)

# 转换为数据框
pcap_data_4 = pd.DataFrame(pcap_features_4, columns=['Timestamp', 'DateSize1', 'DateSize2', 'DateSize3', 'DateSize4'])
pcap_data_2 = pd.DataFrame(pcap_features_2, columns=['Timestamp', 'DateSize1', 'DateSize2'])

# 检查提取的特征数
print(f"共有 {len(pcap_features_4)} 个四序列特征")
print(f"共有 {len(pcap_features_2)} 个双序列特征")

# 清空预测输出文件，仅保留表头
with open('camera_predictions.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Timestamp', 'DateSize1', 'DateSize2', 'DateSize3', 'DateSize4', 'Prediction'])

with open('xiaomi_bulb_off_predictions.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Timestamp', 'DateSize1', 'DateSize2', 'DateSize3', 'DateSize4', 'Prediction'])

with open('xiaomi_bulb_on_predictions.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Timestamp', 'DateSize1', 'DateSize2', 'DateSize3', 'DateSize4', 'Prediction'])

with open('xiaomi_plug_on_off_predictions.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Timestamp', 'DateSize1', 'DateSize2', 'DateSize3', 'DateSize4', 'Prediction'])

with open('door_on_off_predictions.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Timestamp', 'DateSize1', 'DateSize2', 'DateSize3', 'DateSize4', 'Prediction'])

with open('aqara_bulb_on_off_predictions.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Timestamp', 'DateSize1', 'DateSize2', 'Prediction'])

# 准备数据进行预测
if not pcap_data_4.empty:
    prediction_features_4 = pcap_data_4[['DateSize1', 'DateSize2', 'DateSize3', 'DateSize4']]
    prediction_features_4[['Direction1', 'Direction2', 'Direction3', 'Direction4']] = 0  # 填充方向列，保持特征一致
    predictions_4 = model_4.predict(prediction_features_4)

    # 解码预测标签
    predictions_4 = label_encoder_label_4.inverse_transform(predictions_4)

    # 添加预测结果到数据框
    pcap_data_4['Prediction'] = predictions_4

    # 将时间戳转换为北京时间（UTC+8）
    pcap_data_4['Timestamp'] = pd.to_datetime(pcap_data_4['Timestamp'], unit='s').dt.tz_localize('UTC').dt.tz_convert('Asia/Shanghai')

    # 排序时间戳
    pcap_data_4.sort_values(by='Timestamp', inplace=True)


    # 将不同设备的预测结果分类保存到不同文件
    camera_predictions = pcap_data_4[pcap_data_4['Prediction'].str.contains('Xiaomi intelligent camera')]
    camera_predictions[['Timestamp', 'DateSize1', 'DateSize2', 'DateSize3', 'DateSize4', 'Prediction']].to_csv('camera_predictions.csv', index=False)

    xiaomi_bulb_off_predictions = pcap_data_4[pcap_data_4['Prediction'].str.contains(DEVICE_NAMES['xiaomi_bulb_off'])]
    xiaomi_bulb_off_predictions[['Timestamp', 'DateSize1', 'DateSize2', 'DateSize3', 'DateSize4', 'Prediction']].to_csv('xiaomi_bulb_off_predictions.csv', index=False)

    xiaomi_bulb_on_predictions = pcap_data_4[pcap_data_4['Prediction'].str.contains(DEVICE_NAMES['xiaomi_bulb_on'])]
    xiaomi_bulb_on_predictions[['Timestamp', 'DateSize1', 'DateSize2', 'DateSize3', 'DateSize4', 'Prediction']].to_csv('xiaomi_bulb_on_predictions.csv', index=False)

    xiaomi_plug_on_off_predictios = pcap_data_4[pcap_data_4['Prediction'].str.contains(DEVICE_NAMES['xiaomi_plug'])]
    xiaomi_plug_on_off_predictios[['Timestamp', 'DateSize1', 'DateSize2', 'DateSize3', 'DateSize4', 'Prediction']].to_csv('xiaomi_plug_on_off_predictions.csv', index=False)

    aqara_door_and_window_sensor_on_off_predictios = pcap_data_4[pcap_data_4['Prediction'].str.contains(DEVICE_NAMES['door'])]
    aqara_door_and_window_sensor_on_off_predictios[['Timestamp', 'DateSize1', 'DateSize2', 'DateSize3', 'DateSize4', 'Prediction']].to_csv('door_on_off_predictions.csv', index=False)

if not pcap_data_2.empty:
    prediction_features_2 = pcap_data_2[['DateSize1', 'DateSize2']]
    prediction_features_2[['Direction1', 'Direction2']] = 0  # 填充方向列，保持特征一致
    predictions_2 = model_2.predict(prediction_features_2)

    # 解码预测标签
    predictions_2 = label_encoder_label_2.inverse_transform(predictions_2)

    # 添加预测结果到数据框
    pcap_data_2['Prediction'] = predictions_2

    # 将时间戳转换为北京时间（UTC+8）
    pcap_data_2['Timestamp'] = pd.to_datetime(pcap_data_2['Timestamp'], unit='s').dt.tz_localize('UTC').dt.tz_convert('Asia/Shanghai')

    # 排序时间戳
    pcap_data_2.sort_values(by='Timestamp', inplace=True)

    # 将不同设备的预测结果分类保存到不同文件
    aqara_bulb_on_off_predictions = pcap_data_2[pcap_data_2['Prediction'].str.contains(DEVICE_NAMES['aqara_bulb'])]
    aqara_bulb_on_off_predictions[['Timestamp', 'DateSize1', 'DateSize2', 'Prediction']].to_csv('aqara_bulb_on_off_predictions.csv', index=False)

# 设置字体为支持中文的字体
plt.rcParams['font.sans-serif'] = ['Arial Unicode MS']

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from pytz import timezone

# 设置全局字体大小
plt.rcParams.update({'font.size': 18})

# 读取预测结果
camera_predictions = pd.read_csv('camera_predictions.csv')
xiaomi_bulb_on_predictions = pd.read_csv('xiaomi_bulb_on_predictions.csv')
print(xiaomi_bulb_on_predictions)
xiaomi_bulb_off_predictions = pd.read_csv('xiaomi_bulb_off_predictions.csv')
aqara_bulb_predictions = pd.read_csv('aqara_bulb_on_off_predictions.csv')
xiaomi_plug_predictions = pd.read_csv('xiaomi_plug_on_off_predictions.csv')
aqara_door_and_window_sensor_on_off_predictios = pd.read_csv('door_on_off_predictions.csv')

# 合并数据
all_predictions = pd.concat([
    camera_predictions,
    xiaomi_bulb_on_predictions,
    xiaomi_bulb_off_predictions,
    aqara_bulb_predictions,
    xiaomi_plug_predictions,
    aqara_door_and_window_sensor_on_off_predictios
], ignore_index=True)

# 转换并排序时间戳
all_predictions['Timestamp'] = pd.to_datetime(all_predictions['Timestamp'])
all_predictions.sort_values(by='Timestamp', inplace=True)

# 颜色和标记样式
colors = {
    DEVICE_NAMES['camera']: 'dimgray',        # 替换原 red
    DEVICE_NAMES['xiaomi_bulb_off']: 'green',
    DEVICE_NAMES['xiaomi_bulb_on']: 'orange',
    DEVICE_NAMES['aqara_bulb']: 'purple',
    DEVICE_NAMES['xiaomi_plug']: 'skyblue',     # 替换原 cyan
    DEVICE_NAMES['door']: 'mediumpurple'        # 替换原 magenta
}

markers = {
    DEVICE_NAMES['camera']: 'D',
    DEVICE_NAMES['xiaomi_bulb_off']: 'D',
    DEVICE_NAMES['xiaomi_bulb_on']: 'D',
    DEVICE_NAMES['aqara_bulb']: 'D',
    DEVICE_NAMES['xiaomi_plug']: 'D',
    DEVICE_NAMES['door']: 'D'
}

# 获取实际存在设备类型
existing_devices = all_predictions['Prediction'].unique()
filtered_colors = {k: colors[k] for k in existing_devices if k in colors}
filtered_markers = {k: markers[k] for k in existing_devices if k in markers}

# 创建画布和坐标轴
fig, ax = plt.subplots(figsize=(18, 6))
#event_types = list(filtered_colors.keys())
event_types = ['Xiaomi intelligent camera on/off', 'Mijia LED bulb on', 'Mijia LED bulb off', 'Xiaomi intellectual socket on/off', 'Aqara door/window sensor on and off']
spacing = 0.4  # 控制间距
y_positions = []
for i in range(len(event_types)):
    if i == 3:
        y_positions.append(y_positions[-1])  # 和前一个一样
    else:
        y_positions.append(len(set(y_positions)) * spacing)

# 绘制预测事件点
for idx, event_type in enumerate(event_types):
    event_data = all_predictions[all_predictions['Prediction'] == event_type]
    plt.scatter(
        event_data['Timestamp'],
        [y_positions[4-idx]] * len(event_data),
        color=filtered_colors[event_type],
        marker=filtered_markers[event_type],
        label=event_type,
        alpha=0.7,
        s=60
    )

# 设置时间格式和轴标签
ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M:%S', tz=timezone('Asia/Shanghai')))
plt.xlabel("Timestamp (Beijing time)", fontsize=18)
plt.ylabel("Event types", fontsize=18)
plt.title("User Activity Trajectory Chart", fontsize=18)
plt.xticks(fontsize=14)
plt.yticks(fontsize=14)

real_gt = pd.read_csv('true2.csv')
real_gt['Timestamp'] = pd.to_datetime(real_gt['Timestamp'])

# 拆分 ON 和 OFF 时间点
gt_on_timestamps = real_gt[real_gt['Event'] == 'on']['Timestamp'].tolist()
gt_off_timestamps = real_gt[real_gt['Event'] == 'off']['Timestamp'].tolist()
delay_on_timestamps = [ts + pd.Timedelta(seconds=2) for ts in gt_on_timestamps]
delay_off_timestamps = [ts + pd.Timedelta(seconds=2) for ts in gt_off_timestamps]

# y 坐标：on 在下，off 在上
gt_y_on = 0
gt_y_off = max(y_positions)

# 绘制 on（红圈）
# camera 开
plt.scatter(
    gt_on_timestamps,
    [gt_y_off] * len(gt_on_timestamps),
    facecolors='none',
    edgecolors='red',
    marker='o',
    s=80,
    linewidths=1.5,
    label='The actual on event'
)

# 小米灯泡 开
plt.scatter(
    gt_on_timestamps,
    [gt_y_off - 0.4] * len(gt_on_timestamps),
    facecolors='none',
    edgecolors='red',
    marker='o',
    s=80,
    linewidths=1.5,
)

# plug 开
plt.scatter(
    delay_on_timestamps,
    [gt_y_on + 0.4] * len(delay_on_timestamps),
    facecolors='none',
    edgecolors='red',
    marker='o',
    s=80,
    linewidths=1.5,
)

# 绘制 off（橙圈）
# camera 关
plt.scatter(
    gt_off_timestamps,
    [gt_y_off] * len(gt_off_timestamps),
    facecolors='none',
    edgecolors='orange',
    marker='o',
    s=80,
    linewidths=1.5,
    label='The actual off event'
)

# plug 关
plt.scatter(
    delay_off_timestamps,
    [gt_y_on + 0.4] * len(delay_off_timestamps),
    facecolors='none',
    edgecolors='orange',
    marker='o',
    s=80,
    linewidths=1.5,
)

# 小米灯泡 关
plt.scatter(
    gt_off_timestamps,
    [gt_y_off - 0.4] * len(gt_off_timestamps),
    facecolors='none',
    edgecolors='orange',
    marker='o',
    s=80,
    linewidths=1.5,
)

# door 开和关
plt.scatter(
    delay_on_timestamps,
    [gt_y_on] * len(delay_on_timestamps),
    facecolors='none',
    edgecolors='steelblue',
    marker='o',
    s=80,
    linewidths=1.5,
    label='The actual on and off event'
)

# door 开和关
plt.scatter(
    delay_off_timestamps,
    [gt_y_on] * len(delay_off_timestamps),
    facecolors='none',
    edgecolors='steelblue',
    marker='o',
    s=80,
    linewidths=1.5,
)

# 更新 y 轴刻度
plt.yticks([], [])  # 不显示具体的 y 刻度标签
plt.ylabel("Event types", fontsize=18)  # 保留统一的 y 轴标签

# 图例
plt.legend(loc='center left', bbox_to_anchor=(1.02, 0.5), borderaxespad=0., framealpha=0.9, fontsize=14)

# 优化显示并保存
plt.gcf().autofmt_xdate(rotation=30, ha='right')
plt.tight_layout()
plt.savefig('用户活动轨迹图.png', dpi=600, bbox_inches='tight')
plt.show()


