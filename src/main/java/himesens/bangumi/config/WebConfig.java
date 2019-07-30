package himesens.bangumi.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer{
	/**
	 * 访问外部文件的配置
	 */
	@Override
	public void addResourceHandlers(ResourceHandlerRegistry registry){
		registry.addResourceHandler("/files/**").addResourceLocations("file:///D:files/");
		registry.addResourceHandler("/downloads/**").addResourceLocations("file:///D:downloads/");
	}
}
