# Hướng dẫn khởi động ban đầu

## A. Các bước thiết lập môi trường

### 0. Dùng CMD hoặc dùng Terminal của VS code/PowerShell
``` terminal
Crtl + `
```
### 1. Tạo môi trường ảo (venv) - chỉ cần thực hiện 1 lần
```bash
python -m venv venv
```

### 2. Kích hoạt môi trường ảo (venv) - thực hiện mỗi lần mở lại dự án
```bash
.\venv\Scripts\activate
```
> **Lưu ý:** Nếu gặp lỗi sau khi kích hoạt trên terminal VS Code:
>
> ```
> File D:\DA_CNTT\E2EE\venv\Scripts\Activate.ps1 cannot be loaded because running scripts is disabled on this system.
> + CategoryInfo          : SecurityError
> + FullyQualifiedErrorId : UnauthorizedAccess
> ```
> Đây là lỗi do Windows PowerShell chặn chạy script (.ps1) vì lý do bảo mật.
>
> **Cách khắc phục:**
> - Tạm thời cho phép:  
>   ```powershell
>   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
>   ```
> - Cho phép vĩnh viễn:  
>   ```powershell
>   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
>   ```
> - Hoặc kích hoạt venv bằng CMD:  
>   ```cmd
>   .\venv\Scripts\activate
>   ```

> **Dấu hiệu thành công:** Terminal chuyển thành `(venv) PS D:\DA_CNTT\E2EE>`

### 3. Cài đặt thư viện cần thiết
- Cài từng thư viện:
    ```bash
    pip install cryptography
    ```
- Hoặc cài nhanh tất cả từ file `requirements.txt`:
    ```bash
    pip install -r requirements.txt
    ```

> **Lưu ý:** Khi cài thêm thư viện mới, hãy dùng:
> ```bash
> pip freeze > requirements.txt
> ```
> để cập nhật danh sách thư viện vào file `requirements.txt`.

- Các thư viện đã cài nằm trong `venv\Lib\site-packages\`, không cần cài lại trừ khi xóa thư mục venv.

### 4. Kích hoạt lại môi trường ảo mỗi lần mở dự án
- Không cần cài lại thư viện nếu đã cài trước đó.

### 5. Thoát khỏi môi trường ảo
```bash
deactivate
```

