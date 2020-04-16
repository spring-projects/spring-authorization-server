package sample;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = Application.class)
public class ApplicationTest {

    @Test
    public void loadContext(ApplicationContext context) {
        assertThat(context).isNotNull();
    }
}
