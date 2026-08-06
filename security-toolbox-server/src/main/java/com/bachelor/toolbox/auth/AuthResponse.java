package com.bachelor.toolbox.auth;

public record AuthResponse(String token, String tokenType, long expiresIn, UserView user) {
  public record UserView(Long id, String username, String role) {
    static UserView from(User user) {
      return new UserView(user.getId(), user.getUsername(), user.getRole());
    }
  }
}
