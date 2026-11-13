package team.projectpulse.security;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import team.projectpulse.student.Student;
import team.projectpulse.user.MyUserPrincipal;

import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class JwtProviderTest {

    private final JwtEncoder encoder = mock(JwtEncoder.class);
    private final JwtProvider provider = new JwtProvider(encoder);

    @Test
    void rejectsNullPrincipalBeforeEncoding() {
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(null, null, List.of());

        assertThatThrownBy(() -> provider.createToken(authentication))
                .isInstanceOf(BadCredentialsException.class);
        verifyNoInteractions(encoder);
    }

    @Test
    void rejectsNonLocalPrincipalBeforeEncoding() {
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated("external-user", null, List.of());

        assertThatThrownBy(() -> provider.createToken(authentication))
                .isInstanceOf(BadCredentialsException.class);
        verifyNoInteractions(encoder);
    }

    @Test
    void retainsUserIdAuthoritiesAndTwoHourExpiry() {
        Student student = new Student();
        student.setId(42);
        student.setUsername("student@example.test");
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(
                new MyUserPrincipal(student), null, List.of(new SimpleGrantedAuthority("ROLE_student")));
        when(encoder.encode(any())).thenReturn(Jwt.withTokenValue("encoded-token")
                .header("alg", "RS256").subject("student@example.test").build());

        assertThat(provider.createToken(authentication)).isEqualTo("encoded-token");

        ArgumentCaptor<JwtEncoderParameters> parameters = ArgumentCaptor.forClass(JwtEncoderParameters.class);
        verify(encoder).encode(parameters.capture());
        var claims = parameters.getValue().getClaims();
        assertThat(claims.getClaims()).containsEntry("userId", 42)
                .containsEntry("authorities", "ROLE_student").containsEntry("sub", "student@example.test");
        assertThat(ChronoUnit.HOURS.between(claims.getIssuedAt(), claims.getExpiresAt())).isEqualTo(2);
    }
}
