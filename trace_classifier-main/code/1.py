# -*- coding: utf-8 -*-
"""
Modified to support loading pretrained models for prediction
"""
import copy
import os
import torch
from dataset import dataset_json
from model import Net
from mylib import cut_dataset, pre_process_1, drop_empty_data, tailoring_dataset, dataset2flow, \
    dataset_use_hilbertcurve, dataset_use_1dscale
from config import G_CONFIG


def read_dataset(cfg):
    dataset, label2key = dataset_json(cfg.DATASET_NAME)
    cfg.CLASS_NUM = len(label2key)
    print(dataset)
    #cfg.PACKTE_DIM = len(dataset[0][0][0][0]) + 3
    cfg.PACKTE_DIM = 6
    print("cfg.PACKTE_DIM", cfg.PACKTE_DIM)

    print('start dataset2flow()...')
    if cfg.HU2_FLAG:
        dataset = dataset2flow(dataset)

    return dataset, label2key


def load_pretrained_model(cfg, model_path):
    """Load pretrained model from file"""
    model = Net(cfg)
    model = model.to(cfg.DEVICE)
    model.load_state_dict(torch.load(model_path, map_location=cfg.DEVICE))
    model.eval()  # Set to evaluation mode
    return model


def predict_with_model(cfg, model, dataset, label2key):
    """Use pretrained model to make predictions on dataset"""
    # Preprocess the dataset
    print(f"预处理前样本数: {len(dataset)}")
    if cfg.FLOW_CUT_FALG:
        dataset = tailoring_dataset(dataset, cfg.FLOW_CUT_SIZE)
        print(f"裁剪后样本数: {len(dataset)}")
    drop_empty_data(dataset)
    print(f"过滤空数据后样本数: {len(dataset)}")

    if cfg.PACKET2FLOW == '2dCNN':
        dataset = dataset_use_hilbertcurve(dataset, cfg.SIZE_2dCNN)

    if cfg.SCALE_1dCNN and cfg.PACKET2FLOW == '1dCNN':
        dataset = dataset_use_1dscale(dataset, cfg.SCALE_SIZE)

    # 使用明确的全部数据作为测试集
    test_data = [[sample[0], sample[1]] for sample in dataset]  # 保持[特征,标签]结构
    print(f"测试集样本数: {len(test_data)}")  # 应该输出200

    # Preprocess
    test_data, x_norm = pre_process_1(test_data, x_norm=None)

    print(f"Predicting on {len(test_data)} samples...")

    y_true = []
    y_pred = []
    pred_probs = []

    with torch.no_grad():
        for i in range(len(test_data)):
            try:
                X = test_data[i][0]  # Data
                Y = test_data[i][1]  # True label

                # Convert to tensor and predict
                input_X = copy.deepcopy(X)
                output = model.forward(input_X, cfg.DEVICE)

                # Get predicted class
                pred = output.argmax(dim=1, keepdim=True).item()

                # Get probabilities (softmax)
                prob = torch.nn.functional.softmax(output, dim=1).cpu().numpy()[0]

                y_true.append(Y)
                y_pred.append(pred)
                pred_probs.append(prob)

                if i % 100 == 0:
                    print(f"Processed {i}/{len(test_data)} samples")

            except Exception as e:
                print(f"Error processing sample {i}: {str(e)}")
                continue

    # Convert to class names if label2key is available
    if label2key:
        y_true_names = [label2key[y] for y in y_true]
        y_pred_names = [label2key[y] for y in y_pred]
    else:
        y_true_names = y_true
        y_pred_names = y_pred

    return {
        'true_labels': y_true,
        'pred_labels': y_pred,
        'probabilities': pred_probs,
        'true_label_names': y_true_names,
        'pred_label_names': y_pred_names
    }


def save_predictions(results, output_file):
    """Save prediction results to file"""
    with open(output_file, 'w') as f:
        f.write("True Label,Predicted Label,True Label Name,Predicted Label Name,Probabilities\n")
        for true, pred, true_name, pred_name, probs in zip(
                results['true_labels'],
                results['pred_labels'],
                results['true_label_names'],
                results['pred_label_names'],
                results['probabilities']
        ):
            prob_str = ",".join([f"{p:.4f}" for p in probs])
            f.write(f"{true},{pred},{true_name},{pred_name},{prob_str}\n")
    print(f"Predictions saved to {output_file}")


def main():
    torch.multiprocessing.set_start_method('spawn')

    cfg = G_CONFIG()

    # 1. Read dataset
    dataset, label2key = read_dataset(cfg)
    print(f"原始数据集样本数: {len(dataset)}")

    # 2. Load pretrained model
    model_path = "/Users/mac/Desktop/trace_classifier-main/code/output/20230505_test/model_paras_TF_LSTM+ATTLSTM+ATT_pcap_TTFTT_1_best.pt"  # Change this to your model path
    model = load_pretrained_model(cfg, model_path)

    # 3. Make predictions
    results = predict_with_model(cfg, model, dataset, label2key)

    # 4. Save results
    output_file = os.path.join(cfg.OUTPATH, "predictions.csv")
    save_predictions(results, output_file)

    # 5. Print some stats
    correct = sum(1 for t, p in zip(results['true_labels'], results['pred_labels']) if t == p)
    accuracy = correct / len(results['true_labels'])
    print(f"\nPrediction Accuracy: {accuracy:.4f}")

    # You can add more evaluation metrics here as needed


if __name__ == '__main__':
    main()