package ru.jankbyte.spring.jwtauth.config;

import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Configuration;
import ru.jankbyte.spring.jwtauth.Main;

@Configuration(proxyBeanMethods = false)
@ConfigurationPropertiesScan(basePackageClasses = {Main.class})
public class AppConfig {
}
