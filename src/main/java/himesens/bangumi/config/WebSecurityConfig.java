package himesens.bangumi.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{
	

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception{
		//在内存中创建用户，用户名、密码、权限
		auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder()).
		 withUser("admin").password(new BCryptPasswordEncoder().encode("123456")).roles("USER","ADMIN");
		//注册自定义的完全管理员权限
		//auth.authenticationProvider(HC);
		//加入数据库验证类
		//auth.userDetailsService(myUserDetailsService).passwordEncoder(new BCryptPasswordEncoder());
	}
	
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/downloads/**","/staticfiles/**","/android/**","/api/**","/css/**","/js/**","/images/**","/icons/**","/error","/login_p","/register","/template");  
    }
    
	@Override
	protected void configure(HttpSecurity http) throws Exception{
		//出现thymeleaf无法加载iframe情况时的设置
		http.headers().frameOptions().disable();
		//允许跨域设置
		http.csrf().disable();
		http
			.authorizeRequests()
			
			.antMatchers("/writeblog").hasRole("ADMIN")
			//.antMatchers("/static/**", "/favicon.ico","/error","/login_p").permitAll()
			//.antMatchers("/user/**").hasRole("USER")
			//.antMatchers("/admin/**").hasRole("ADMIN")
			.and()
			//.successHandler(new LoginSuccessHandler())
			//.formLogin().loginPage("/login_p").loginProcessingUrl("/login").permitAll()
			.formLogin().loginPage("/login_p").permitAll().loginProcessingUrl("/login")
			.defaultSuccessUrl("/writeblog")
			.failureUrl("/errorpage")
		    
			//.formLogin().loginPage("/login").permitAll()
			//.formLogin().loginPage("/login").defaultSuccessUrl("/index")
			.usernameParameter("myusername").passwordParameter("mypassword")
			.and()
			.logout().logoutUrl("/logout").logoutSuccessUrl("/login_p").permitAll();
			//.logout().logoutUrl("/logout").logoutSuccessUrl("/login")
			//.and()
			//.exceptionHandling().accessDeniedHandler(myAccessDeniedHandler);
			//.and().sessionManagement().maximumSessions(2).expiredUrl("/login?expired").sessionRegistry(sessionRegistry());
	}
}
