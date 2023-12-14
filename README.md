# HDU-OAUTH
本项目仅针对HDU的oauth，并且仅考虑了我自己的使用场景

# Before start
修改 CTFd/config.ini 添加
```c
[extra]
# The extra section can be used to specify additional values to be loaded into CTFd's configuration
HDU_OA_CLIENT_ID =
HDU_OA_CLIENT_SECRET =
HDU_OA_REDIRECT_URI =
```

修改 docker-compose.yml 添加对应值
```c
- HDU_OA_CLIENT_ID=
- HDU_OA_CLIENT_SECRET=
- HDU_OA_REDIRECT_URI=
```
