/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.owasp.webgoat.container.WebGoat;
import org.owasp.webgoat.container.i18n.Language;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.context.WebApplicationContext;

/**
 * Pruebas negativas de {@code POST /service/admin/users/{username}/reset-password}, con el
 * contexto completo y la cadena de seguridad real.
 *
 * <ul>
 *   <li>Autorización: un usuario sin WEBGOAT_ADMIN recibe 403.
 *   <li>Autenticación: una petición anónima no llega al controlador.
 *   <li>Validación de entradas: un username fuera de [a-z0-9-]{6,45} recibe 400.
 *   <li>Manejo de errores: un usuario inexistente recibe 404 sin filtrar detalles internos.
 * </ul>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = WebGoat.class)
@TestPropertySource(
    locations = {
      "classpath:/application-webgoat.properties",
      "classpath:/application-webgoat-test.properties"
    })
class AdminResetPasswordNegativeTest {

  private static final String URL = "/service/admin/users/{username}/reset-password";

  @Autowired private WebApplicationContext wac;
  @MockitoBean private ClientRegistrationRepository clientRegistrationRepository;
  @MockitoBean private Language language;
  @MockitoSpyBean private UserService userService;

  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    mockMvc = webAppContextSetup(wac).apply(springSecurity()).build();
  }

  @Test
  @WithMockUser(username = "alumno-uno", authorities = "WEBGOAT_USER")
  void autorizacion_usuarioSinRolAdmin_recibe403() throws Exception {
    mockMvc.perform(post(URL, "webgoat")).andExpect(status().isForbidden());

    verify(userService, never()).resetPassword(anyString(), anyString());
  }

  @Test
  void autenticacion_peticionAnonima_noLlegaAlControlador() throws Exception {
    // Petición AJAX: 401
    mockMvc
        .perform(post(URL, "webgoat").header("x-requested-with", "XMLHttpRequest"))
        .andExpect(status().isUnauthorized());
    // Petición normal: redirección al login
    mockMvc
        .perform(post(URL, "webgoat"))
        .andExpect(status().is3xxRedirection())
        .andExpect(header().string("Location", containsString("/login")));

    verify(userService, never()).resetPassword(anyString(), anyString());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "ab", // demasiado corto
        "USUARIO-MAYUS", // mayúsculas no permitidas
        "con espacios", // espacios
        "user_name", // guion bajo
        "robert';drop--", // intento de inyección
        "..%2e-admin", // traversal
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // más de 45 caracteres
      })
  @WithMockUser(username = "admin-uno", authorities = "WEBGOAT_ADMIN")
  void validacion_usernameInvalido_recibe400(String username) throws Exception {
    mockMvc.perform(post(URL, username)).andExpect(status().isBadRequest());

    verify(userService, never()).resetPassword(any(), any());
  }

  @Test
  @WithMockUser(username = "admin-uno", authorities = "WEBGOAT_ADMIN")
  void errores_usuarioInexistente_recibe404SinFiltrarDetalles() throws Exception {
    mockMvc
        .perform(post(URL, "no-existe-nadie"))
        .andExpect(status().isNotFound())
        .andExpect(content().string(not(containsString("User not found"))))
        .andExpect(content().string(not(containsString("Exception"))))
        .andExpect(content().string(not(containsString("temporaryPassword"))))
        .andExpect(content().string(not(containsString("at org."))));
  }
}
