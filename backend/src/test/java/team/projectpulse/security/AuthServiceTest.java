package team.projectpulse.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import team.projectpulse.instructor.Instructor;
import team.projectpulse.instructor.converter.InstructorToInstructorDtoConverter;
import team.projectpulse.section.Section;
import team.projectpulse.student.Student;
import team.projectpulse.student.converter.StudentToStudentDtoConverter;
import team.projectpulse.user.MyUserPrincipal;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class AuthServiceTest {

    private final JwtProvider jwtProvider = mock(JwtProvider.class);
    private final AuthService authService = new AuthService(jwtProvider,
            new StudentToStudentDtoConverter(), new InstructorToInstructorDtoConverter());

    @Test
    void rejectsNullPrincipalBeforeBuildingLoginInfo() {
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(null, null, List.of());

        assertThatThrownBy(() -> authService.createLoginInfo(authentication))
                .isInstanceOf(BadCredentialsException.class);
        verifyNoInteractions(jwtProvider);
    }

    @Test
    void rejectsNonLocalPrincipalBeforeBuildingLoginInfo() {
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated("external-user", null, List.of());

        assertThatThrownBy(() -> authService.createLoginInfo(authentication))
                .isInstanceOf(BadCredentialsException.class);
        verifyNoInteractions(jwtProvider);
    }

    @Test
    void rejectsMissingRolesWithoutNullPointerOrToken() {
        Student student = new Student();
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(
                new MyUserPrincipal(student), null, List.of());

        assertThatThrownBy(() -> authService.createLoginInfo(authentication))
                .isInstanceOf(BadCredentialsException.class);
        verifyNoInteractions(jwtProvider);
    }

    @Test
    void stillReturnsStudentInfoAndToken() {
        Student student = new Student();
        student.setId(42);
        student.setRoles("student");
        student.setSection(new Section());
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(
                new MyUserPrincipal(student), null, List.of());
        when(jwtProvider.createToken(authentication)).thenReturn("student-token");

        Map<String, Object> result = authService.createLoginInfo(authentication);

        assertThat(result).containsEntry("token", "student-token");
        assertThat(result.get("userInfo")).isEqualTo(new StudentToStudentDtoConverter().convert(student));
    }

    @Test
    void stillReturnsInstructorInfoAndToken() {
        Instructor instructor = new Instructor();
        instructor.setId(43);
        instructor.setRoles("admin instructor");
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(
                new MyUserPrincipal(instructor), null, List.of());
        when(jwtProvider.createToken(authentication)).thenReturn("instructor-token");

        Map<String, Object> result = authService.createLoginInfo(authentication);

        assertThat(result).containsEntry("token", "instructor-token");
        assertThat(result.get("userInfo")).isEqualTo(new InstructorToInstructorDtoConverter().convert(instructor));
    }
}
