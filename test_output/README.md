# NIDS Real-time Feature Extraction System

Hệ thống trích xuất đặc trưng thời gian thực cho Network Intrusion Detection System (NIDS).

## 📋 Tổng quan

Hệ thống này bắt gói tin từ giao diện mạng (Ethernet, Wi-Fi) và trích xuất **6 đặc trưng (features)** để huấn luyện mô hình AI phát hiện xâm nhập mạng.

### 6 Features được trích xuất

| # | Feature | Mô tả | Phát hiện |
|---|---------|-------|-----------|
| F1 | Packet Rate | Tốc độ gói tin/giây | DDoS, Flood |
| F2 | SYN/ACK Ratio | Tỷ lệ SYN trên tổng | SYN Flood |
| F3 | Distinct Ports | Số cổng đích khác nhau | Port Scan |
| F4 | Payload Length | Độ dài trung bình payload | Buffer Overflow |
| F5 | Fail Rate | Tỷ lệ kết nối lỗi (RST, ICMP) | Brute Force, Scan |
| F6 | Context Score | Điểm ngữ cảnh từ payload | SQLi, XSS, Command Injection |

## 🏗️ Kiến trúc hệ thống

```
┌─────────────────────────────────────────────────────────────────┐
│                         main.py (CLI)                           │
│                   Command-line Interface                        │
└───────────────────────────┬─────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│   Sniffer     │   │ PacketParser  │   │   Processor   │
│ (Bắt gói tin) │──▶│ (Phân tích)   │──▶│ (Tính toán)   │
└───────────────┘   └───────────────┘   └───────────────┘
                            │                   │
                            ▼                   ▼
                    ┌───────────────┐   ┌───────────────┐
                    │  LayerInfo    │   │ PacketWindow  │
                    │ (Data Model)  │   │ (Sliding Win) │
                    └───────────────┘   └───────────────┘
                                                │
                    ┌───────────────────────────┘
                    ▼
        ┌───────────────────────────────────────┐
        │        Feature Calculators            │
        │  F1  │  F2  │  F3  │  F4  │  F5  │ F6 │
        └───────────────────────────────────────┘
                            │
                            ▼
                    ┌───────────────┐
                    │   CSV Output  │
                    │ (6 features)  │
                    └───────────────┘
```

## 📦 Cài đặt

### Yêu cầu
- Python 3.8+
- Windows (với quyền Administrator)
- Npcap hoặc WinPcap đã cài đặt

### Bước cài đặt

```bash
# Clone repository
git clone <repository-url>
cd System

# Tạo virtual environment (khuyến nghị)
python -m venv .venv
.venv\Scripts\activate

# Cài đặt dependencies
pip install -r requirements.txt
```

## 🚀 Sử dụng

### Chế độ Real-time (Per-packet)

Mỗi gói tin = 1 dòng CSV. Dùng cho IDS thời gian thực.

```bash
# Chạy với quyền Administrator
python main.py -i "Ethernet" -o output.csv

# Giới hạn số gói tin
python main.py -i "Wi-Fi" -o features.csv -c 1000
```

### Chế độ Aggregate

Mỗi 1 giây = 1 dòng CSV. Dùng cho huấn luyện AI.

```bash
python main.py -i "Ethernet" -o training.csv --mode aggregate
```

### Tham số CLI

| Tham số | Mô tả | Mặc định |
|---------|-------|----------|
| `-i, --interface` | Tên giao diện mạng (bắt buộc) | - |
| `-o, --output` | File CSV đầu ra | `realtime_features.csv` |
| `-c, --count` | Số gói tin tối đa | Không giới hạn |
| `-m, --mode` | Chế độ output: `per-packet` hoặc `aggregate` | `per-packet` |

### Tên giao diện phổ biến (Windows)
- `Ethernet` - Kết nối có dây
- `Wi-Fi` - Kết nối không dây
- `Loopback Pseudo-Interface 1` - Localhost

## 📁 Cấu trúc thư mục

```
System/
├── main.py                 # Entry point - CLI
├── requirements.txt        # Python dependencies
├── README.md               # Tài liệu này
│
├── core/                   # Core modules
│   ├── sniffer.py          # Bắt gói tin (Scapy wrapper)
│   ├── packet_parser.py    # Phân tích gói tin thành LayerInfo
│   ├── layer_info.py       # Data model cho thông tin gói tin
│   ├── window_packet.py    # Sliding window lưu lịch sử
│   └── processor.py        # Điều phối tính toán 6 features
│
├── feature/                # Feature calculators
│   ├── feature_base.py     # Abstract base class
│   └── feature_logic.py    # 6 feature implementations
│
├── config/                 # Configuration
│   └── ai_config.py        # Ngưỡng chuẩn hóa, hằng số
│
└── test/                   # Unit tests
    └── test_all_features.py
```

## 📊 Output Format

### Schema note
- Các file CSV cũ trong thư mục `test_output/` có thể vẫn dùng header `f6_ctx_norm` (di sản từ phiên bản trước).
- Từ phiên bản hiện tại, output mới dùng `f6_ctx_score` và **F6 không chuẩn hóa về [0,1]** mà là **{-1, 0, 1}**.

File CSV đầu ra có 6 cột:
- F1–F5 được chuẩn hóa về **[0, 1]**
- F6 là **context score rời rạc** trong **{-1, 0, 1}**

```csv
f1_rate_norm,f2_syn_norm,f3_port_norm,f4_len_norm,f5_fail_norm,f6_ctx_score
0.0033,0.0000,0.0200,0.0000,0.0000,0.0000
0.0067,0.5000,0.0400,0.0320,0.0000,0.0000
```

### Ý nghĩa giá trị
- **0.0**: Bình thường / An toàn
- **1.0**: Bất thường / Nghi ngờ tấn công
- Giá trị cao hơn = Nghi ngờ tấn công cao hơn

Riêng **F6**:
- **-1**: Safe pattern (ví dụ upload hợp lệ)
- **0**: Neutral
- **1**: Malicious pattern (SQLi/XSS/command/path traversal/webshell signatures)

## ⚠️ Lưu ý quan trọng

1. **Quyền Administrator**: Cần chạy với quyền Admin để bắt gói tin trên Windows
2. **Npcap**: Phải cài đặt [Npcap](https://npcap.com/) trước khi sử dụng
3. **Memory**: Hệ thống tự động cleanup sau mỗi 100,000 packets
4. **Dừng chương trình**: Nhấn `Ctrl+C` để dừng an toàn

## 🔧 Configuration

Các ngưỡng chuẩn hóa được định nghĩa trong `config/ai_config.py`:

| Feature | Ngưỡng MAX | Công thức |
|---------|------------|-----------|
| Packet Rate | 3000 pkt/s | `raw / 3000` |
| SYN Ratio | 1.0 | `SYN / (SYN + ACK)` |
| Distinct Ports | 50 | `ports / 50` |
| Payload Length | 1500 bytes | `avg_len / 1500` |
| Fail Rate | 1.0 | `failed / total` |
| Context Score | Discrete | `-1`, `0`, `1` |

## 📝 License

IAP491 Project - FPT University
