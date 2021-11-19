public class Credential {
    private String username;
    private String url;
    private String password;

    Credential(String username, String url, String password) {
        this.username = username;
        this.url = url;
        this.password = password;
    }

    String getUsername() {
        return username;
    }

    String getUrl() {
        return url;
    }

    String getPassword() {
        return password;
    }
}
