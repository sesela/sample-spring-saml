package net.sesela.sample.spring.saml.config;

import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.EmptyKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.log.SAMLLogger;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.websso.*;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/css/**", "/fonts/**", "/images/**", "/js/**", "/saml/metadata");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				.anyRequest().authenticated()
				.and()
				.httpBasic();
	}

	@Bean(name = "parserPool", initMethod = "initialize")
	public StaticBasicParserPool idpParserPool() {
		return new StaticBasicParserPool();
	}

	@Bean
	public HTTPMetadataProvider ipdHttpMetadataProvider() throws MetadataProviderException {
		HTTPMetadataProvider provider = new HTTPMetadataProvider("https://idp.ssocircle.com/idp-meta.xml", 5000);
		provider.setParserPool(idpParserPool());
		return provider;
	}

	@Bean("metadata")
	public CachingMetadataManager ipdMetadata() throws MetadataProviderException {
		List<MetadataProvider> providers = new ArrayList<>();
		providers.add(ipdHttpMetadataProvider());
		CachingMetadataManager metadataManager = new CachingMetadataManager(providers);
		return metadataManager;
	}

	@Bean
	public ExtendedMetadata spExtendedMetadata() {
		ExtendedMetadata metadata = new ExtendedMetadata();
		metadata.setSignMetadata(false);
		metadata.setIdpDiscoveryEnabled(true);
		return metadata;
	}

	@Bean
	public MetadataGenerator spMetadataGenerator() {
		MetadataGenerator generator = new MetadataGenerator();
		generator.setEntityId("replaceWithUniqueIdentifier");
		generator.setExtendedMetadata(spExtendedMetadata());
		return generator;
	}

	@Bean("metadataGeneratorFilter")
	public MetadataGeneratorFilter spMetadataGeneratorFilter() {
		MetadataGeneratorFilter filter = new MetadataGeneratorFilter(spMetadataGenerator());
		return filter;
	}

	@Bean("keyManager")
	public KeyManager keyManager() {
		KeyManager keyManager = new EmptyKeyManager();
		return keyManager;
	}

	@Bean
	public static BeanFactoryPostProcessor postProcessorSAMLBootstrap() {
		return new SAMLBootstrap();
	}

	@Bean
	public MetadataDisplayFilter spMetadataDisplayFilter() {
		return new MetadataDisplayFilter();
	}

	@Bean
	public SAMLContextProvider spContextProvider() {
		return new SAMLContextProviderImpl();
	}

}
