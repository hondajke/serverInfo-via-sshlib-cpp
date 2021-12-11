#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>

void free_session(ssh_session session) {
    ssh_disconnect(session);
    ssh_free(session);
}
//Обработчик ошибок
void error(ssh_session session) {
    fprintf(stderr, "Error: %s\n", ssh_get_error(session));
    free_session(session);
    exit(-1);
}
//Закрытие соединения
void close_channel(ssh_channel channel) {
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
}
//Выполнение команды в bash
void execute_command(const char* command, ssh_channel channel, ssh_session session) {
    unsigned int nbytes;
    int rc;
    char buffer[1024];

    channel = ssh_channel_new(session);
    if (channel == NULL) exit(-1);

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) error(session);

    rc = ssh_channel_request_exec(channel, command);
    if (rc != SSH_OK) error(session);

    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    while (nbytes > 0) {
        fwrite(buffer, 1, nbytes, stdout);
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    }
    close_channel(channel);
}

int main() {
    ssh_session session;
    ssh_channel channel = NULL;
    int rc, port = 22;
    char buffer[1024];
    unsigned int nbytes;
    printf("Session...\n");
    session = ssh_new();
    if (session == NULL) exit(-1);
    //Настройка сессии
    ssh_options_set(session, SSH_OPTIONS_HOST, "192.168.1.10");
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(session, SSH_OPTIONS_USER, "tom");
    //Подключение
    printf("Connecting...\n");
    rc = ssh_connect(session);
    if (rc != SSH_OK) error(session);
    //Аутентификация
    printf("Password Autentication...\n");
    rc = ssh_userauth_password(session, NULL, "tom");
    if (rc != SSH_AUTH_SUCCESS) error(session);
    //Вывод данных
    printf("Server information\n\n");
    printf("hostname: ");
    execute_command("hostname", channel, session);
    printf("motherboard model: ");
    execute_command("sudo dmidecode -s baseboard-manufacturer | tr '\n' ' '; sudo dmidecode -s baseboard-product-name", channel, session);
    printf("cpu model: ");
    execute_command("sudo lshw -short -class processor | grep 'processor' | cut -c 39-", channel, session);
    printf("traffic usage: in: ");
    execute_command("sudo ifconfig -s | grep 'enp' | tr -s ' ' | cut -d ' ' -f3 | tr -d '\n'", channel, session);
    printf("Kb out: ");
    execute_command("sudo ifconfig -s | grep 'enp' | tr -s ' ' | cut -d ' ' -f7 | tr -d '\n'", channel, session);
    printf("Kb\n");
    printf("memory: ");
    execute_command("free --mega | grep 'Mem:' | tr -s ' ' | cut -d ' ' -f3 | tr -d '\n'", channel, session);
    printf("Mb/ ");
    execute_command("free --mega | grep 'Mem:' | tr -s ' ' | cut -d ' ' -f2 | tr -d '\n'", channel, session);
    printf("Mb\n");
    printf("release: ");
    execute_command("cat /etc/os-release | grep 'PRETTY_NAME' | tr -d '\"=' | tr -d 'PRETTY_NAME'", channel, session);

    free_session(session);

    return 0;
}
