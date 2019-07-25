# SampleStore
### 1.8. 登录-控制器层

首先，设计请求：

	请求路径：/user/handle_login.do
	请求类型：POST
	请求参数：username, password, HttpSession
	响应方式：ResponseResult

然后，添加处理请求的方法：

	@RequestMapping(value="/handle_login.do", method=RequestMethod.GET)
	@ResponseBody
	public ResponseResult handleLogin(String username, String password, HttpSession session) {
		// 声明返回值
		// try {
		// 调用业务层对象的login()方法，并获取返回值
		// 在session中封装必要的数据
		// 在返回值对象中封装state值为1
		// } catch (XXXException e) {
		// 在返回值对象中封装state值为-1
		// 在返回值对象中封装message值为e.getMessage
		// } catch (XXXException e) {
		// 在返回值对象中封装state值为-2
		// 在返回值对象中封装message值为e.getMessage
		// }
		// 返回
	}

编写完成后，代码如下：
# 商城项目

## 1. 数据分析

通过观察静态页面，当前项目中至少包括以下类型的数据：商品，商品分类，用户 ，收货地址，购物车，收藏，订单。

关于以上数据，处理的顺序可以是：用户，收货地址，商品分类，商品，购物车，收藏，订单。

每项数据的处理都应该是：增，查，删，改。

每个功能的处理都应该是：持久层，业务层，控制器层，前端界面。

## 2. 用户数据处理 

### 2.1. 用户注册

#### 2.1.1. 密码加密

加密算法有：对称加密、非对称加密。无论是哪种，在已知加密过程的各项数据参数后，都可以根据密文运算得到原文。

通常，密码的存储并不使用这些加密算法，而是使用消息摘要（Message Digest）算法。

消息摘要的特征有：

- 使用特定的摘要算法，得到的摘要数据的长度是固定的；

- 使用相同的原文，必然得到相同的摘要；

- 使用不同的原文，可能得到相同的摘要，但是，机率非常非常低；

- 消息摘要是不可被逆运算的！

常见的消息摘要算法有SHA家族（Secure Hash Algorithm）算法，MD系列。

在Java原生API中，有`java.security.MessageDigest`类，用于处理消息摘要运算，但是，使用相对繁琐，通常，会使用其它API来实现，例如：

	String password = "1234";
	String md5 = org.springframework.util.DigestUtils.md5DigestAsHex(
				password.getBytes()).toUpperCase();
	System.out.println(md5);
		
	md5 = org.apache.commons.codec.digest.DigestUtils.md5Hex(password).toUpperCase();
	System.out.println(md5);
		
	String sha256 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(password).toUpperCase();
	System.out.println(sha256);

在Spring和Apache中都有`DigestUtils`工具类，可以用于摘要运算，前者需要添加Spring的依赖，后者需要添加`commons-codec`的依赖：

	<dependency>
		<groupId>commons-codec</groupId>
		<artifactId>commons-codec</artifactId>
		<version>1.10</version>
	</dependency>

**关于MD5解密**

如果希望根据摘要数据，进行逆运算，得到原文，才算是破解，本身就是对摘要算法的误解！

在网上大量的在线破解，本质上都是“反查”，即，在这些网站的数据库中，记录了大量的原文与摘要的对应关系，对于简单的原文执行的摘要运算，可能都已经被收录了，所以，可以查询到原文，但是，使用相对比较复杂的原文运算得到的摘要数据，往往都是无法反查的，因为这些网站可能没有收集这些数据！

所以，MD5依然是不可逆运算的，用于密码加密，是安全的！

**进一步提升密码的安全程度**

简单的密码存在反查风险，通常，可改进的方案有：

1. 增加原文的复杂程度，例如`P@ss8888W0rD`；

2. 多重加密；

3. 在加密过程中添加盐；

4. 综合以上应用方式。

#### 2.1.2. 用户注册－持久层

应该先创建项目：`cn.jacob.store` / `SampleStore`。

创建数据库：`jacob_store`

创建数据表：

	CREATE TABLE t_user (
		id INT AUTO_INCREMENT,
		username VARCHAR(20) UNIQUE NOT NULL,
		password CHAR(32) NOT NULL,
		avatar VARCHAR(100),
		gender INT,
		phone VARCHAR(20),
		email VARCHAR(50),
		salt CHAR(36),
		is_delete INT,
		created_time DATETIME,
		created_user VARCHAR(20),
		modified_time DATETIME,
		modified_user VARCHAR(20),
		PRIMARY KEY(id)
	) DEFAULT CHARSET=UTF8;

先创建实体类的基类`cn.jacob.store.entity.BaseEntity`，它是一个抽象类，在其中声明关于日志的4个属性。

然后创建实体类`cn.jacob.store.entity.User`，继承自以上`BaseEntity`类，属性设计与以上数据表的字段设计保持一致！

检查持久层的相关配置是否正确，重点在于：`db.properties`中`url`属性中的数据库名称、`password`属性的值、`spring-dao.xml`中关于MyBatis的配置项中，接口文件的包名和映射文件的文件夹名称。

创建持久层接口`cn.jacob.store.mapper.UserMapper`，并声明抽象方法：

	Integer insert(User user);

	User findUserByUsername(String username);

然后，在`src\main\resources\mappers\UserMapper.xml`中配置以上2个方法的映射。

#### 2.1.2. 用户注册－业务层

通常，会创建业务异常的基类`cn.jacob.store.service.ex.ServiceException`。

根据分析，注册时可能抛出2种异常，则先创建这2个异常类：`cn.jacob.store.service.ex.UsernameConflictException`和`cn.jacob.store.service.ex.InsertDataException`，这2个异常都应该继承自`ServiceException`。

创建`cn.jacob.store.service.IUserService`业务层接口，然后声明抽象方法，原则是需要什么功能，就声明什么方法：

	User reg(User user) 
		throws UsernameConflictException, 
			InsertDataException;

然后，创建业务层的实现类`cn.jacob.store.service.impl.UserServiceImpl`，添加`@Service`注解，并检查`spring-service.xml`中组件扫描的包是否匹配，声明持久层对象`@Autowired private UserMapper userMapper;`

实现以上方法：

	public User reg(User user) throws UsernameConflictException {
		// 根据尝试注册的用户名查询用户数据
		// 判断是否查询到数据
			// 是：查询到数据，即用户名被占用，则抛出UsernameConflictException异常
			// 否：没有查询到数据，即用户名没有被占用，则执行插入用户数据，获取返回值
			// 执行返回
	}

还需要添加以下辅助方法：

	private User insert(User user) {
		// 在参数user中封装那些不由外部提供的数据：
		// 1. 生成随机盐，并封装到user中
		// 2. 取出user中原密码执行加密，并封装回user中
		// 3. 设置isDelete为0
		// 4. 日志的4项

		// 调用持久层对象的方法实现功能，并获取返回值
		// 判断返回值是否为1
			// 是：返回参数对象 
			// 否：抛出InsertDataException异常
	}

	private User findUserByUsername(String username) {
		// TODO 检查用户名基本格式是否正确
		// 调用持久层对象的方法实现功能
	}

	private String getEncrpytedPassword(String password, String salt) {
		// 将原密码加密
		// 将盐加密
		// 将以上2个加密结果拼接
		// 循环5次加密
		// 返回
	}

完成后，执行单元测试。
## 2. 用户数据处理 

### 2.1. 用户注册

#### 2.1.3. 用户注册－控制器层

创建`cn.jacob.store.entity.ResponseResult`类：

	public class ResponseResult<T> {
		private Integer state = 200;	// 操作状态
		private String message;		// 提示信息
		private T data;				// 数据

		public ResponseResult(Integer state, Exception e) {
			super();
			this.state = state;
			this.message = e.getMessage();
		}
	}

创建控制器类的基类`cn.jacob.store.controller.BaseController`，声明为`abstract`抽象类，并且不需要添加注解！在这个类，添加方法实现对异常的处理：

	@ExceptionHandler(ServiceException.class)
	@ResponseBody
	public ResponseResult<Void> handleException(Exception e) {
		// 判断异常类型，并进行处理
		if (e instanceof UsernameConflictException) {
			// 用户名被占用
			return new ResponseResult<Void>(401, e);
		} else if (e instanceof InsertDataException) {
			// 插入数据错误
			return new ResponseResult<Void>(501, e);
		}
	}

创建控制器类`cn.jacob.store.controller.UserController`，添加`@Controller`注解和`@RequestMapping("/user")`注解，继承自以上`BaseController`。

检查`spring-mvc.xml`中组件扫描的包是否正确！

在类中声明`@Autowired private IUserService userService;`

分析所处理的请求：

	请求路径：/user/handle_reg.do
	请求类型：POST
	请求参数：User
	响应方式：ResponseResult

则，在控制器类中添加处理请求的方法：

	@RequestMapping(value="/handle_reg.do", method=RequestMethod.GET)
	@ResponseBody
	// 当前方法的返回值中的泛型表示需要给客户端的结果中，除了操作状态和提示信息以外，还给什么数据
	public ResponseResult<Void> handleReg(User user) {
		// 调用业务层对象实现注册
		userService.reg(user);
		// 执行返回
		return new ResponseResult<Void>();
	}

完成后，通过`http://localhost:8080/jacobStore/user/handle_reg.do?username=chrome&password=1234`在浏览器中测试，如果无误，则完成，并将请求类型限制为`POST`。

**关于响应方式**

目前，响应方式可以是：转发、重定向、正文。

其中，转发和重定向都会导致用户端的界面跳转，而正文可以是JSON格式，如果通过AJAX提交请求并处理结果，则用户端的界面可以不发生跳转。

主流的做法是服务器只响应正文，且是JSON格式，好处在于前端界面可以结合AJAX技术，实现局部刷新，进而有流量消耗小、响应速度快的优势，并且，由于服务器只提供数据服务，完全不考虑界面的处理，则对客户端也就没有要求，客户端可以自行使用任何技术进行处理，所以，也就能够适用于多种不同的客户端，例如：浏览器、Android APP、iOS APP等。

使用这样的做法，也可以使得开发人员的分工更加明确，即服务器端的开发人员不需要考虑任何客户端技术。

### 2.2. 用户登录

#### 2.2.1. 用户登录-持久层

关于登录，持久层的任务只有**根据用户名查询用户数据**，此前已经完成该功能，则检查：**查询结果中是否包含登录时必要的字段：id, username, password, salt。**

如果检查无误，则持久层无须进一步开发。

#### 2.2.2. 用户登录-业务层

在`cn.jacob.store.service.ex`中创建2个新的异常类：`UserNotFoundException`和`PasswordNotMatchException`，均继承自`ServiceException`。

基于**需要执行什么功能，就在业务层接口中声明什么方法**的原则，首先，在业务层接口中声明：

	User login(String username, String password) throws UserNotFoundException, PasswordNotMacthException;

然后，在业务层实现类中实现以上方法：

	public User login(String username, String password) throws UserNotFoundException, PasswordNotMacthException{
		// 根据用户名查询用户数据
		// 判断是否查询到数据
			// 是：查询到与用户名匹配的数据，获取盐值
				// 基于参数密码与盐值进行加密
				// 判断加密结果与用户数据中的密码是否匹配
					// 是：返回用户数据
					// 否：密码不正确，抛出PasswordNotMacthException异常
			// 否：没有与用户名匹配的数据，则抛出UserNotFoundException异常
	}

完成后，执行单元测试。

#### 2.2.3. 用户登录-控制器层

分析需要处理的请求：

	请求路径：/user/handle_login.do
	请求类型：POST
	请求参数：username(*), password(*), HttpSession
	响应方式：ResponseResult

调用业务层方法实现功能时，新抛出的异常：

	UserNotFoundException
	PasswordNotMatchException

基于以上分析，应该先在`BaseController`中处理异常的方法中，添加对以上2种异常的处理！

然后，在`UserController`中添加处理请求的方法：

	@RequestMapping(value="/handle_login.do", method=RequestMethod.GET)
	@ResponseBody
	public ResponseResult<Void> handleLogin(
		@RequestParam("username") String username,
		@RequestParam("password") String password,
		HttpSession session) {
		// 调用业务层对象的login()方法，并获取返回值
		// 将用户id和用户名封装到session中
		// 返回
	}

完成后，通过`http://localhost:8080/jacobStore/user/handle_login.do?username=root&password=1234`在浏览器中测试，测试通过后，将请求类型限制为`POST`。

## 2. 用户数据处理 

### 2.2. 用户登录

#### 2.2.3. 用户登录-控制器层

关于用户提交的数据，需要验证基本数据格式，然后，再执行后续操作，即：如果数据基本格式都不正确，例如没有输入正确格式的用户名，根本就不需要查询数据库，就可以视为登录失败！

**通常，可以视为：用户提交的所有数据都是不可靠的！**

在服务器端，接收到数据的第一时刻，就应该检验数据的有效性，即验证数据的基本格式和内容的组成，甚至内容中是否包括非法内容（敏感词等等），而第一时刻，可以是过滤器或拦截器，也可以是控制器，通常是在控制器中进行处理。

处理方式可以使用正则表达式进行判断。

通常，建议在业务层执行相同的判断！其实，绝大部分的数据处理流程是`Controller > Service`，所以，如果控制器已经判断过，则业务层是不需要判断的！但是，也存在某些业务功能的设计，是不需要经过控制器，就可以直接调用业务层的！在这种情况下，可以视为没有验证数据就开始执行业务，则是不安全的做法，所以，业务层也应该验证数据的有效性！

其实，完整的验证应该是：前端页面通过JavaScript验证，如果数据合法，则允许提交到服务器端，在服务器端，首先由控制器验证，如果数据合法，则允许调用业务层对象执行数据访问，然后，由业务层再次验证数据的有效性，如果数据合法，则允许向后继续执行。所以，总的来说，在前端页面、控制器、业务层都需要验证数据！其实，只有业务层的验证，才是真正的保障数据安全的验证，而前序的验证，是为了减轻后续操作的负担，避免将不符合规则的数据向后提交而产生的验证。

#### 2.2.4. 前端页面

参考注册页面的开发流程和代码。

### 2.3. 修改密码

#### 2.3.1. 持久层

首先，持久层中必须存在**修改密码**的功能，对应的SQL语句大致是：

	UPDATE t_user SET password=? WHERE id=?

以上设计中，只体现了修改密码的功能，而并不考虑修改密码的业务，毕竟，不是所有人或所有应用场景中，都需要验证原密码才可以执行修改！

基于本次修改功能是需要验证原密码的，该验证操作将在业务层来组织，则业务层将需要**获取该用户的原密码**功能，由于用户登录后，会在session中存入id，所以，在持久层应该实现**根据id查询该用户的原始密码**功能：

	SELECT password, salt FROM t_user WHERE id=?

所以，实现**修改密码**时，持久层需要完成以上2个任务，则在`UserMapper.java`接口中添加新的抽象方法：

	User findUserById(Integer id);

	Integer updatePassword(
		@Param("id") Integer id, 
		@Param("password") String password);

然后，在`UserMapper.xml`中配置以上方法的映射：

	<!-- 根据用户id查询用户数据 -->
	<!-- User findUserById(Integer id) -->
	<select id="findUserById"
		resultType="cn.jacob.store.entity.User">
		SELECT 
			password, salt
		FROM 
			t_user
		WHERE 
			id=#{id}
	</select>
	
	<!-- 更新密码 -->
	<!-- Integer updatePassword(
			@Param("id") Integer id, 
			@Param("password") String password); -->
	<update id="updatePassword">
		UPDATE t_user
		SET password=#{password}
		WHERE id=#{id}
	</update>

完成后，执行单元测试。

#### 2.3.2. 业务层

首先，在业务层接口中添加抽象方法：

**设计业务方法原则1：需要执行什么任务，就设计什么方法！**

**设计业务方法原则2：只考虑操作成功的情况下，需要返回什么数据，不通过返回值来表达操作成功与否！**

**设计业务方法原则3：每个持久层的方法，在业务层中，都有一个直接调用它的方法！**

	void changePassword(
		Integer id, String oldPassword, String newPassword); 

然后，在实现类实现以上方法：

	public void changePassword(
		Integer id, String oldPassword, String newPassword) {
		// 根据id查询用户数据
		// 判断用户数据是否存在（可能用户登录后数据被删除）
		// 是：用户数据存在，获取盐值
		// 将oldPassword加密
		// 将加密后的密码，与刚才查询结果中的密码对比
			// 是：基于盐和newPassword加密
			// 更新密码
			// 否：原密码错误，抛出PasswordNotMatchException
		// 否：用户数据不存在，抛出UserNotFoundException
	}

**组织业务的代码，不直接调用持久层中的方法**

	private User findUserById(Integer id) {
		return userMapper.findUserById(id);
	}

	private Integer updatePassword(Integer id, String password) {
		直接调用持久层功能来实现，获取返回值
		判断返回值
	}

完成后，执行单元测试。

#### 2.3.3. 控制器层

先确定是否抛出了新的异常，如果有，则在`BaseController`中进行处理，本次需要处理的有`UpdateDataException`。

然后，设计**处理修改密码**的请求：

	请求路径：/user/change_password.do
	请求类型：POST
	请求参数：old_password(*), new_password(*), HttpSession
	响应方式：ResponseResult

然后，在`UserController`中添加处理请求的方法：

	@RequestMapping(value="/change_password.do", method=RequestMethod.GET)
	@ResponseBody
	public ResponseResult<Void> handleChangePassword(
		@ReuqestParam("old_password") String oldPassword,
		@ReuqestParam("new_password") String newPassword,
		HttpSession session) {
		// 验证密码格式

		// 从Session中获取当前用户的id
		// 通过业务执行修改密码
		userService.changePassword(id, oldPassword, newPassword);
		// 返回
	} 

完成后，先登录，通过`http://localhost:8080/jacobStore/user/change_password.do?old_password=1234&new_password=8888`，测试完成后，将请求类型限制为`POST`类型。

**关于登录，请使用拦截器！**

### 2.3. 修改密码

#### 2.3.4. HTML访问过滤器

修改密码的页面`password.html`应该需要登录，才允许访问，由于拦截器`Interceptor`是SpringMVC中的组件，而当前项目中`DispatcherServlet`只处理了`*.do`的请求，所以，所有`*.html`的请求将不经过SpringMVC的执行流程，拦截器也就无法对HTML页面的访问进行拦截操作。

针对这个问题，需要使用Java EE中的过滤器`Filter`来实现，创建`HtmlAccessFilter`，并且，在`web.xml`中添加配置，对`*.html`进行过滤：

	<!-- 配置HTML访问过滤器 -->
	<filter>
		<filter-name>HtmlAccessFilter</filter-name>
		<filter-class>cn.jacob.store.filter.HtmlAccessFilter</filter-class>
	</filter>

	<filter-mapping>
		<filter-name>HtmlAccessFilter</filter-name>
		<url-pattern>*.html</url-pattern>
	</filter-mapping>

然后，编写过滤器中的代码，规则包括：1) 白名单中的页面直接放行；2) 已登录的直接放行；3) 其它的html页面的访问全部拦截。

其中，白名单应该在`init()`方法中创建，只执行一次。

放行的表现是调用过滤器链的`doChain()`方法。

具体代码如下：

	/**
	 * HTML访问过滤器
	 */
	public class HtmlAccessFilter implements Filter {
		/**
		 * 白名单，允许直接访问的页面列表
		 */
		private List<String> whiteList = new ArrayList<String>();
		
		public void init(FilterConfig arg0) throws ServletException {
			// 确定白名单
			whiteList.add("register.html");
			whiteList.add("login.html");
			whiteList.add("footerTemplate.html");
			whiteList.add("leftTemplate.html");
			whiteList.add("topTemplate.html");
			// 输出
			System.out.println("无需登录的页面列表：");
			for (String page : whiteList) {
				System.out.println(page);
			}
		}
	
		public void doFilter(ServletRequest arg0, 
				ServletResponse arg1, 
				FilterChain filterChain)
				throws IOException, ServletException {
			// 获取当前页面
			HttpServletRequest request 
				= (HttpServletRequest) arg0;
			String uri = request.getRequestURI();
			int beginIndex = uri.lastIndexOf("/") + 1;
			String fileName = uri.substring(beginIndex);
			System.out.println("当前请求页面：" + fileName);
			
			// 判断当前访问的是哪个页面
			// 如果是无需登录的页面，直接放行，例如：login.html
			if (whiteList.contains(fileName)) {
				System.out.println("\t无需登录，直接放行");
				// 继续执行过滤器链
				filterChain.doFilter(arg0, arg1);
				return;
			}
			
			// 如果是需要登录的页面，判断session，决定放行或重定向
			HttpSession session
				= request.getSession();
			if (session.getAttribute("uid") != null) {
				// Session中有uid，表示已登录，直接放行
				System.out.println("\t已经登录，直接放行");
				// 继续执行过滤器链
				filterChain.doFilter(arg0, arg1);
				return;
			}
			
			// 执行到此处，表示当前页面不在白名单中，且未登录，则拦截
			// 拦截的表现是：重定向到登录页
			System.out.println("\t拦截当前页面，将重定向到登录页！");
			HttpServletResponse response
				= (HttpServletResponse) arg1;
			response.sendRedirect("login.html");
		}
	
		public void destroy() {
		}
	}

### 2.4. 修改个人资料

#### 2.4.1. 持久层

该功能对应的SQL语句大致是：

	UPDATE 
		t_user 
	SET 
		gender=?, phone=?, email=?
	WHERE id=?

所以，在持久层接口中添加抽象方法：

	Integer updateInfo(User user);

然后，配置以上抽象方法的映射。

完成后，执行单元测试。

#### 2.4.2. 业务层

在业务接口中声明抽象方法：

	void changeInfo(User user);

在业务层实现类中实现以上方法：

	public void changeInfo(User user) {
		// 判断用户id是否存在
		if (user.getId() == null) {
			throw new UpdateDataException("id...");
		}

		// 检查其它数据的格式

		// 判断用户数据是否存在于数据表中
		User data = findUserById(user.getId());
		if (data == null) {
			throw new UserNotFoundException("...");
		}

		// 补全需要更新的数据
		user.setModifiedUser(data.getUsername());
		user.setModifiedTime(new Date());

		// 执行更新
		updateInfo(user);
	}

	private void updateInfo(User user) {
		Integer rows = userMapper.updateInfo(user);
		if (rows != 1) {
			throw new UpdateDataException("....");
		}
	}

**注意：请检查UserMapper.xml中关于findUserById()的映射中，必须查询username字段，如果没有，请补全。**

完成后，执行单元测试。

#### 2.4.3. 控制器层

先检查是否抛出了新的异常，此次抛出的是`UserNotFoundException`和`UpdateDataException`，这2个都是处理过的异常，则无需再次处理！如果自行抛出了**手机号码格式异常**、**电子邮件格式异常**，则应该在`BaseController`中对这2个新的异常进行处理！

然后，设计处理**修改个人信息**的请求：

	请求路径：/user/change_info.do
	请求类型：POST
	请求参数：User(phone, email, gender), HttpSession(用户id)
	响应方式：ResponseResult<Void>
	是否拦截：是，但无需修改配置

然后，在`UserController`中添加处理请求的方法：

	@RequestMapping(value="/change_info.do", method=RequestMethod.GET)
	@ResponseBody
	public ResponseResult<Void> handleChangeInfo(
		User user, HttpSession session) {
		// 获取id
		// 执行
		// 返回
	}

完成后，通过`http://localhost:8080/jacobStore/user/change_info.do?phone=x&email=x&gender=1`在浏览器中测试（由于有了登录拦截器，未登录时，会被重定向），测试完成后，将请求类型限制为`POST`。

### 2.4. 修改个人资料

#### 2.4.4. 前端页面

不同于**注册**、**登录**、**修改密码**，此次显示的**修改个人资料**页面，应该是**刚打开页面时，就直接显示当前登录的用户的资料**！这个效果，可以通过**刚打开页面时，就向服务器请求当前用户的资料，在处理响应结果时，直接将内容显示到各控件中**来实现。

要实现这个需求，需要服务器端能够**根据当前登录的用户的id获取用户的用户名、性别、手机号码、邮箱**。首先，持久层已经有`findUserById(Integer id)`方法可以适用于当前需求，应该检查持久层的映射中，查询的字段是否完整；然后，此前的业务层实现类中已经存在该方法，但是，由于接口中没有声明该方法，且最终控制器中声明的是接口的对象，为了保证方法的调用，应该先在接口中声明`User findUserById(Integer id);`方法，再将实现类原有的方法的访问权限修改为`public`；再接下来，应该保证控制器能够响应所需的数据，则：

	请求路径：/user/info.do
	请求类型：GET
	请求参数：HttpSession
	响应方式：ResponseResult<User>
	是否拦截：是，但无需修改配置

所以，在`UserController`中添加处理请求的方法：

	@RequestMapping("/info.do")
	@ResponseBody
	public ResponseResult<User> getInfo(HttpSession session) {
		// 获取uid
		// 查询
		// 创建返回值对象
		// 把查询结果封装到返回值对象的data属性中
		// 返回
	}

### 2.5. 文件上传

#### 2.5.1. 创建WEB页面

文件上传的HTML页面中需要表单，且`method="post`和`enctype="multipart/form-data"`，使用的控件是`<input type="file" />`：

	<form method="post"  action="upload.do"
		enctype="multipart/form-data">
		<div><input name="file" type="file" /></div>
		<div><input type="submit" value="上传" /></div>
	</form>

#### 3.2. 添加依赖

SpringMVC中的文件上传依赖apache的`commons-fileupload`，所以，添加依赖：

	<!-- 文件上传 -->
	<dependency>
		<groupId>commons-fileupload</groupId>
		<artifactId>commons-fileupload</artifactId>
		<version>1.3.3</version>
	</dependency>

#### 3.3. 配置CommonsMultipartResolver

使用SpringMVC的上传，必须在Spring的配置文件中配置`CommonsMultipartResolver`，且`id`必须是`multipartResolver`，该节点可以有更多配置，也可以不添加配置，最简化配置如下：

	<!-- CommonsMultipartResolver -->
	<bean id="multipartResolver"
		class="org.springframework.web.multipart.commons.CommonsMultipartResolver" />

#### 3.4. 创建控制器处理请求

在服务器端处理上传请求时，需要将用户提交的上传文件声明为`CommonsMultipartFile`类型，它表示用户上传的文件，调用该参数对象的`transferTo(File)`方法即可将文件保存在服务器端的某个位置，通常，推荐将文件保存在`webapp`目录下，以便于用户可以通过HTTP协议进行访问，并且，通常还会专门创建某个文件夹，用于存储用户上传的文件，通过`HttpServletRequest`对象的`getServletContext.getRealPath(String)`方法可以获取到`webapp`下某文件夹的实际路径：

	@Controller
	public class UploadController {
	
		@RequestMapping("/upload.do")
		public String handleUpload(
				HttpServletRequest request,
				@RequestParam("file") CommonsMultipartFile file) 
					throws IllegalStateException, IOException {
			// CommonsMutltpartFile是SpringMVC封装的上传数据
			String parentPath = request
				.getServletContext().getRealPath("upload");
			// 确定文件夹，是webapp下的upload
			File parentFile = new File(parentPath);
			// 确定文件名
			String fileName = "1.jpg";
			// 确定上传的文件存储到的目标文件
			File dest = new File(parentFile, fileName);
			// 将上传的数据进行存储
			file.transferTo(dest);
			return null;
		}
		
	}

通常，上传的文件都必须限制文件类型，可以通过`CommonsMultipartFile`对象的`String getContentType()`方法获取文件的MIME类型，例如`image/jpeg`，更多类型可以在Tomcat的`conf/web.xml`中查找。

且上传的文件必须限制文件大小，因为过大的文件可能导致上传体验较差，并且，产生的流量消耗较大，占用较多的服务器端存储空间，通过`CommonsMultipartFile`对象的`long getSize()`方法可以获取文件的大小，例如`12345`，是以字节为单位的。

还可以通过`CommonsMultipartFile`对象的`String getOriginalFileName()`方法获取原始文件名，即用户端的文件名，主要通过该文件名截取出文件的扩展名，用于最终保存文件。

最终保存的文件名应该自定义命名规则，以保证每个用户上传的文件彼此不会覆盖，通常会使用时间、随机数等作为文件名的某个部分。

除此以外，还可以通过`getBytes()`和`getInputStream()`获取用户上传的原始数据/流，然后自行创建输出流，将数据写入到服务器端的文件中，而自定义输出流的写入，可以根据实际情况提高写入效率！

关于在Spring的配置文件中配置的`CommonsMultipartResolver`，可以配置以下属性：

- maxUploadSize：最大上传大小，即每次上传的文件不允许超过多少字节！假设同时上传5个文件，则5个文件的大小总和不允许超过设置值。

- maxUploadSizePerFile：每个上传的文件不允许超过多少字节，因为单次上传其实可以选中多个文件！假设同时上传5个文件，则每个文件的大小都不允许超过设置值，而5个文件的总大小允许超过设置值。.

- maxInMemorySize：上传的文件在内存中最大占多少空间。

- defaultEncoding：默认编码。

**注意：在HTML页面中，在<input type="file" />标签中添加multiple="multiple"，则上传时可以同时选中多个文件提交上传，且，在服务器端处理时，处理请求的方法中应该声明CommonsMultipartFile[] files参数来接收多个文件的数据。**

### 2.6. 头像上传

#### 2.6.1. 分析

上传头像时，应该把头像文件的路径存储到数据表中，例如`upload/201812021610041.jpg`，后续，当需要显示头像时，使用`<img src="upload/201812021610041.jpg" />`即可显示。

所以，上传头像的操作主要是：1) 将文件存储到指定的目录中；2) 将文件的路径存储到数据表中。

#### 2.6.2. 持久层

基于以上分析，在上传头像功能中，持久层的任务是将文件的路径存储到数据表中，即**更新当前用户的avatar字段值**。

所以，在持久层接口中声明抽象方法：

	Integer updateAvatart(
		@Param("id") Integer id,
		@Param("avatar") String avatar);

执行的SQL语句格式为：

	UPDATE t_user SET avatar=? WHERE id=?

基于以上内容配置映射，完成后，测试。

#### 2.6.3. 业务层

在业务层接口中声明抽象方法：

	void changeAvatar(Integer id, String avatar) 
		throws UserNotFoundException, 
			UpdateDataException;

在业务层实现类中实现以上方法：

	public void changeAvatar(Integer id, String avatar) 
		throws UserNotFoundException, 
			UpdateDataException{
		if (findUserById(id) == null) {
			throw new UserNotFoundException("...");
		}
		updateAvatar(id, avatar);
	}

	private void updateAvatar(Integer id, String avatar) {
		Integer rows = userMapper.updateAvatar(id, avatar);
		if (rows != 1) {
			throw new UpdateDataException("...");
		}
	}

#### 2.6.4. 控制器层

先按照上传文件的开发流程，完成：添加依赖、配置`CommonsMultipartResolver`，然后，设计请求：

	请求路径：/user/upload.do
	请求类型：POST
	请求参数：HttpServletRequest, HttpSession, CommonsMultipartFile
	响应方式：ResponseResult<String>
	是否拦截：是，登录拦截，但无需修改配置 

在`UserController`中添加处理请求的方法：

	public static final long MAX_UPLOAD_SIZE = 1 * 1024 * 1024;

	public static final List<String> 
		CONTENT_TYPE_WHITE_LIST 
			= new ArrayList<String>();

	@PostConstruct
	public void init() {
		CONTENT_TYPE_WHITE_LIST.add("image/jpeg");
		CONTENT_TYPE_WHITE_LIST.add("image/png");
	}

	@RequestMapping(value="/upload.do", 
		method=RequestMethod.POST)
	@ResponseBody
	public ResponseResult<String> handleUpload(
		HttpServletRequest request,
		HttpSession session,
		CommonsMultipartFile file) {
		// 检查上传的文件大小
		long fileSize = file.getSize();
		if (fileSize > MAX_UPLOAD_SIZE) {
			return new ResponseResult<String>(?, "");
		}

		// 检查上传的文件类型
		String contentType = file.getContentType();
		if (!CONTENT_TYPE_WHITE_LIST.contains(contentType)) {
			return new ResponseResult<String>(?, "");
		}

		// 确定保存上传文件的文件夹名称
		String uploadDirName = "upload";

		// 获取id
		Integer id = xxxx;

		// 确定文件夹对象
		String uploadDirPath = request.getServletContext().getRealPath(uploadDirName);
		File uploadDir = new File(uploadDirPath);
		if (!uploadDir.exists()) {
			uploadDir.mkdirs();
		}

		// 确定文件名
		int beginIndex = file.getOriginalFileName().lastIndexOf(".");
		String suffix = file.getOriginalFileName().substring(beginIndex);
		String fileName = getFileName(id) + suffix;

		// 创建dest对象，是File类型	
		File dest = new File(uploadDir, fileName);
		// 执行保存
		file.transferTo(dest);
		// 更新数据表
		String avatar = uploadDirName + "/" + fileName;
		userService.changeAvatar(id, avatar);
		return null;
	}

	private String getFileName(Integer id) {
		// 基于id和时间返回文件名称
	}

	/**
	 * 用户上传的头像的最大尺寸，单位：字节
	 */
	private static final long AVATAR_MAX_SIZE = 1 * 1024 * 1024;
	/**
	 * 头像类型白名单
	 */
	private static final List<String> AVATAR_TYPE_WHITE_LIST = new ArrayList<String>();
	
	@PostConstruct
	public void init() {
		AVATAR_TYPE_WHITE_LIST.add("image/jpeg");
		AVATAR_TYPE_WHITE_LIST.add("image/png");
	}
	
	@RequestMapping(value="/upload.do",
		method=RequestMethod.POST)
	@ResponseBody
	public ResponseResult<String> handleUpload(
			HttpServletRequest request,
			HttpSession session,
			CommonsMultipartFile file) {
		// 检查是否上传了文件
		if (file.isEmpty()) {
			return new ResponseResult<String>(601, "读取文件中断，文件路径可能已经发生变化！");
		}
		// 检查文件大小
		long fileSize = file.getSize();
		if (fileSize > AVATAR_MAX_SIZE) {
			return new ResponseResult<String>(601, "读取文件中断，文件路径可能已经发生变化！");
		}
		// 检查文件类型
		String contentType = file.getContentType();
		if (!AVATAR_TYPE_WHITE_LIST
				.contains(contentType)) {
			return new ResponseResult<String>(601, "读取文件中断，文件路径可能已经发生变化！");
		}
		
		// 获取当前登录的用户的id
		Integer id = getUidFromSession(session);
		
		// 用户上传的文件存储到的文件夹的名称
		String uploadDirName = "upload";
		// 用户上传的文件存储到的文件夹的路径
		String parentDirPath
			= request.getServletContext()
				.getRealPath(uploadDirName);
		// 用户上传的文件存储到的文件夹
		File parentDir = new File(parentDirPath);
		// 确保文件夹存在
		if (!parentDir.exists()) {
			parentDir.mkdirs();
		}
		
		// 获取原始文件名
		String originalFileName = file.getOriginalFilename();
		// 获取原始文件的扩展名
		int beginIndex = originalFileName.lastIndexOf(".");
		String suffix = originalFileName.substring(beginIndex);
		// 用户上传的文件存储的文件名
		String fileName = getFileName(id) + suffix;
		// 确定用户上传的文件在服务器端的路径
		String avatar = uploadDirName + "/" + fileName;
		
		// 用户上传的文件存储到服务器端的文件对象
		File dest = new File(parentDir, fileName);
		
		// 将用户上传的文件存储到指定文件夹
		try {
			file.transferTo(dest);
		} catch (IllegalStateException e) {
			return new ResponseResult<String>(601, "读取文件中断，文件路径可能已经发生变化！");
		} catch (IOException e) {
			return new ResponseResult<String>(602, "读取数据出错！文件可能已被移动、删除，或网络连接中断！");
		}
		// 将用户的头像数据更新到数据表
		userService.changeAvatar(id, avatar);
		
		// 返回
		ResponseResult<String> rr
			= new ResponseResult<String>();
		rr.setData(avatar);
		return rr;
	}
	
	/**
	 * 获取上传文件的文件名，文件名的命名规则是：uid-yyyyMMddHHmmss
	 * @param uid 用户id
	 * @return 匹配格式的字符串
	 */
	private String getFileName(Integer uid) {
		Date date = new Date();
		SimpleDateFormat sdf = new SimpleDateFormat(
				"yyyyMMddHHmmss");
		return uid + "-" + sdf.format(date);
	}
	
# ------------------------------------------------------

抛出的新的异常：

	300-请求参数异常-RequestArgumentException

	303-上传文件大小超出限制-UploadFileSizeLimitException

	304-上传文件类型异常-UploadFileContentTypeException

	305-上传状态异常-UploadStateException

	306-上传文件读写异常-UploadIOException

调整后的控制器：

	@RequestMapping(value="/upload.do",
		method=RequestMethod.POST)
	@ResponseBody
	public ResponseResult<String> handleUpload(
			HttpServletRequest request,
			HttpSession session,
			CommonsMultipartFile file) {
		// 检查是否上传了文件
		if (file.isEmpty()) {
			throw new RequestArgumentException(
				"没有选择上传的文件，或上传的文件的内容为空！");
		}
		// 检查文件大小
		long fileSize = file.getSize();
		if (fileSize > AVATAR_MAX_SIZE) {
			throw new UploadFileSizeLimitException(
				"上传的文件大小超出限制！限制值为" + (AVATAR_MAX_SIZE / 1024) + "KByte。");
		}
		// 检查文件类型
		String contentType = file.getContentType();
		if (!AVATAR_TYPE_WHITE_LIST
				.contains(contentType)) {
			throw new UploadFileContentTypeException(
				"上传文件类型错误！允许的文件类型：" + AVATAR_TYPE_WHITE_LIST);
		}
		
		// 获取当前登录的用户的id
		Integer id = getUidFromSession(session);
		
		// 用户上传的文件存储到的文件夹的名称
		String uploadDirName = "upload";
		// 用户上传的文件存储到的文件夹的路径
		String parentDirPath
			= request.getServletContext()
				.getRealPath(uploadDirName);
		// 用户上传的文件存储到的文件夹
		File parentDir = new File(parentDirPath);
		// 确保文件夹存在
		if (!parentDir.exists()) {
			parentDir.mkdirs();
		}
		
		// 获取原始文件名
		String originalFileName = file.getOriginalFilename();
		// 获取原始文件的扩展名
		int beginIndex = originalFileName.lastIndexOf(".");
		String suffix = originalFileName.substring(beginIndex);
		// 用户上传的文件存储的文件名
		String fileName = getFileName(id) + suffix;
		// 确定用户上传的文件在服务器端的路径
		String avatar = uploadDirName + "/" + fileName;
		
		// 用户上传的文件存储到服务器端的文件对象
		File dest = new File(parentDir, fileName);
		
		// 将用户上传的文件存储到指定文件夹
		try {
			file.transferTo(dest);
		} catch (IllegalStateException e) {
			throw new UploadStateException("读取文件中断，文件路径可能已经发生变化！");
		} catch (IOException e) {
			throw new UploadIOException("读取数据出错！文件可能已被移动、删除，或网络连接中断！");
		}
		// 将用户的头像数据更新到数据表
		userService.changeAvatar(id, avatar);
		
		// 返回
		ResponseResult<String> rr
			= new ResponseResult<String>();
		rr.setData(avatar);
		return rr;
	}

## 3. 收货地址管理

### 3.1. 增加收货地址

#### 3.1.1.  增加收货地址-持久层

**数据表**

	CREATE TABLE t_address (
		id INT AUTO_INCREMENT,
		uid INT NOT NULL,
		recv_name VARCHAR(16) NOT NULL,
		recv_province CHAR(6),
		recv_city CHAR(6),
		recv_area CHAR(6),
		recv_district VARCHAR(30),
		recv_address VARCHAR(50),
		recv_phone VARCHAR(20),
		recv_tel VARCHAR(20),
		recv_zip CHAR(6),
		recv_tag VARCHAR(10),
		is_default INT,
		created_time DATETIME,
		created_user VARCHAR(20),
		modified_time DATETIME,
		modified_user VARCHAR(20),
		PRIMARY KEY(id)
	) DEFAULT CHARSET=UTF8;

> 数据库设计范式

**实体类**

创建`cn.jacob.store.entity.Address`，继承自`BaseEntity`。

**接口**

通常，每种类型的数据都有1张对应的数据表，有1个对应的实体类，也有1个对应的持久层接口。

创建`cn.jacob.store.mapper.AddressMapper`接口，并声明抽象方法：

	Integer insert(Address address);

**映射**

复制`UserMapper.xml`得到`AddressMapper.xml`，删除原有配置，将根节点的`namespace`属性值改为`cn.jacob.store.mapper.AddressMapper`，然后，配置以上抽象方法的映射：

	<insert id="insert" parameterType="xx"
		useGeneratedKeys="true"
		keyProperty="id">
		INSERT INTO t_address (
			uid, recv_name ...
		) VALUES (
			#{uid}, #{recvName} ...
		)
	</insert>

完成后，创建新的测试类，执行测试。

#### 3.1.2.  增加收货地址-业务层

在业务层存在业务逻辑：如果当前增加的收货地址是当前用户的第1条收货地址，则是默认收货地址，否则，不是默认收货地址。

所以，需要**根据用户查询有多少条收货地址**功能，则应该先在持久层添加抽象方法：

	Integer getCountByUid(Integer uid);

对应的SQL语句是：

	SELECT COUNT(id) FROM t_address WHERE uid=?

则继续配置相关映射，并执行测试。

创建业务接口`cn.jacob.store.serivce.IAddressService`，并声明抽象方法：

	Address addnew(Address address);

创建业务实现类`cn.jacob.store.service.AddressServiceImpl`，使用`@Service("addressService")`注解，声明`@Autowired private AddressMapper addressMapper`，并实现以上接口，并重写抽象方法：

	public Address addnew(Address address) {
		// 完善数据：recv_district，示例：河北省，石家庄市，长安区

		// 完善数据：is_default
		// 第1次增加的是默认，否则不默认
		Integer count = getCountByUid(address.getUid());
		address.setIsDefault(count > 0 ? 0 : 1);

		// 执行插入数据
		Address result = insert(address);
		return result;
	}

	private Address insert(Address address) {
		Integer rows = addressMapper.insert(address);
		if (rows != 1) {
			throw new InsertDataException("...");
		} else {
			return address;
		}
	}

	private Integer getCountByUid(Integer uid) {
		return addressMapper.getCountByUid(uid);
	}


#### 3.1.3.  增加收货地址-控制器层

#### 3.1.4.  增加收货地址-前端页面

### 3.2. 收货地址列表

### 3.3. 删除收货地址

### 3.4. 修改收货地址

## 3. 收货地址管理

### 3.1. 增加收货地址

#### 3.1.2.  增加收货地址-业务层

此次业务操作中并没有抛出新的异常，所以，无需在`BaseController`中添加处理新的异常。

然后，设计处理请求：

	请求路径：/address/addnew.do
	请求类型：POST
	请求参数：Address, HttpSession
	响应方式：ResponseResult<Void>
	是否拦截：是，登录拦截，需要添加新的配置

由于需要登录拦截，则应该在`spring-mvc.xml`的拦截器配置中，添加对`/address/**`路径的拦截！

然后，创建`cn.jacob.store.controller.AddressController`，继承自`BaseController`，添加`@Controller`和`@RequestMapping("/address")`这2个注解，并声明`@Autowired private IAddressService addressService;`对象。

然后，在控制器类中添加处理请求的方法：

	@RequestMapping(value="/addnew.do", method=RequestMethod.GET)
	@ResponseBody
	public ResponseResult<Void> handleAddnew(
		Address address, HttpSession session) {
		// 获取uid
		// 将uid封装到address
		// 调用业务层执行增加
		// 返回
		return null;
	}

完成后，可通过`http://localhost:8080/jacobStore/address/addnew.do?recvName=XiaoLiu&recvProvince=330000&recvCity=330100&recvArea=330101`在浏览器进行测试，完成后，将请求类型限制为`POST`。


## 3. 收货地址管理

### 3.2. 显示收货地址列表

#### 3.2.1. 显示收货地址列表-持久层

在接口中声明：

	List<Address> getList(Integer uid);

配置映射，SQL语句是：

	SELECT 
		id, 
		recv_tag	AS	recvTag, 
		recv_name	AS	recvName, 
		recv_district	AS	recvDistrict, 
		recv_address	AS	recvAddress, 
		recv_phone	AS	recvPhone, 
		is_default	AS	isDefault
	FROM 
		t_address
	WHERE 
		uid=#{uid}		
	ORDER BY 
		is_default DESC, id DESC
	
#### 3.2.2. 显示收货地址列表-业务层

声明并实现与持久层相同的方法。

完成后，执行单元测试。

#### 3.2.3. 显示收货地址列表-控制层

此次并没有抛出新的异常，则无须处理异常。

分析需要处理的请求：

	请求路径：/address/list.do
	请求类型：GET
	请求参数：HttpSession
	响应方式：ResponseResult<List<Address>>
	是否拦截：是，登录拦截，但无需修改配置

则，处理请求的方法：

	@RequestMapping("/list.do")
	@ResponseBody 
	public ResponseResult<List<Address>> showList(HttpSession session) {
		// 1. 获取数据
		// 2. 创建返回值
		// 3. 将数据封装到返回值对象
		// 4. 执行返回
	}

### 3.3. 设置默认收货地址

#### 3.3.1. 设置默认收货地址-持久层

在接口中：

	Integer setNonDefault(Integer uid);

	Integer setDefault(Integer id);

	Address findAddressById(Integer id);

对应的SQL语句是：

	UPDATE t_address SET is_default=0 WHERE uid=?

	UPDATE t_address SET is_default=1 WHERE id=?

	SELECT * FROM t_address WHERE id=?

#### 3.3.2. 设置默认收货地址-业务层

先创建`AddressNotFoundException`异常类；

在接口中：

	void setDefaultAddress(Integer id, Integer uid) throws AddressNotFoundException, UpdateDataException;

在实现类中：

	public void setDefaultAddress(Integer id, Integer uid) {
		// 【1】检查数据是否归属用户
		// 可能抛出：AddressNotFoundException
		// 【2】将该用户的所有地址设置非默认
		// 可能抛出：UpdateDataException
		// 【3】将指定id的地址设置为默认
		// 可能抛出：UpdateDataException
	}

	private Address findAddressById(Integer id) {
		...
	}

	private void setNonDefault(Integer uid) {
		Integer rows = ...
		if (rows < 1) {
			throws new UpdateDataException("...");
		}
	}

	private void setDefault(id) {
		Integer rows = ...
		if (rows < 1) {
			throws new UpdateDataException("...");
		}
	}

## 基于Spring的事务

### 关于事务

事务（Transaction）是某个业务中需要执行的多次数据访问的集合，例如在“设置默认收货地址”时，该功能也称之为一个业务，一个业务可能涉及多次数据操作。

事务可以将多条数据操作形成一个整体，并且，在执行时，要么全部成功，要么全部失败，以保证数据的安全。

所以：当某个业务中涉及2次或更多次的增、删、改操作时（例如1次删除加上1次修改，或2次修改……），应该使用事务！

### 使用事务

在Spring案例中，当某个业务是需要以事务的方式来执行的，在方法之前添加`@Transactional`注解即可！

由Spring管理的事务，默认都是执行完毕后提交的，仅当执行过程中捕获到任何`RuntimeException`时自动回滚！

基于这种工作特性，在开发过程中，必须做法：

- 调用持久层访问数据时，所有的增、删、改操作必须判断受影响的行数，且，行数错误时必须抛出某种异常；

- 在业务层中抛出的异常必须是`RuntimeException`的子孙类；

并且，在Spring的配置文件中，必须配置：

	<!-- DataSourceTransactionManager -->
	<bean id="transactionManager"
		class="org.springframework.jdbc.datasource.DataSourceTransactionManager">
		<!-- 数据源 -->
		<property name="dataSource"
			ref="dataSource" />
	</bean>
	
	<!-- 注解驱动 -->
	<tx:annotation-driven 
		transaction-manager="transactionManager"/>
	

## 3. 收货地址管理

### 3.3. 设置默认收货地址

#### 3.3.3. 设置默认收货地址-控制器层

步骤1：是否需要处理新的异常？有：`AddressNotFoundException`、`AddressAccessException`，所以，需要在`BaseController`中进行处理。

步骤2：设计请求：

	请求路径：/address/set_default.do
	请求类型：不限
	请求参数：id(*)
	响应方式：ResponseResult<Void>
	是否拦截：是，登录拦截，无需修改配置

则处理请求的方法：

	@RequestMapping("/set_default.do")
	@ResponseBody
	public ResponseResult<Void> setDefault(
		@RequestParam("id") Integer id,
		HttpSession session) {
		Integer uid = getUidFromSession(session);
		addressService.setDefaultAddress(id, uid);
		return new ResponseResult<Void>();
	}

### 3.4. 删除收货地址

### 3.4.1. 删除收货地址-持久层

抽象方法：

	Integer deleteById(Integer id);

	Integer getMaxId(Integer uid);

SQL语句：

	DELETE FROM t_address WHERE id=?

	SELECT MAX(id) FROM t_address WHERE uid=?

### 3.4.2. 删除收货地址-业务层

抽象方法：

	void delete(Integer id, Integer uid);

业务分析：

	@Transactional
	根据id查询数据
	检查数据是否存在
		存在：检查数据的uid归属
			归属正常：执行删除
				判断刚才删除的地址是否是默认
				是：当前还有没有收货地址（数量多少）
					不为0：将id最大的数据设置为默认地址
					为0：不需要执行任何任务
				否：不需要执行任何任务
			归属错误：抛出异常AddressAccessException
		不存在：抛出异常AddressNotFoundException
	
代码实现：

	@Transactional
	public void delete(Integer id, Integer uid)
			throws AddressNotFoundException, AddressAccessException, DeleteDataException {
		// 根据id查询数据
		Address data = findAddressById(id);
		// 检查数据是否存在
		if (data != null) {
		    // 存在：检查数据的uid归属
		    if (data.getUid().equals(uid)) {
		        // 归属正常：执行删除
		    	deleteById(id);
		    	// 判断刚才删除的地址是否是默认
		    	if (data.getIsDefault() == 1) {
		            // 是：当前还有没有收货地址（数量多少）
		    		Integer count = getCountByUid(uid);
		    		if (count > 0) {
		                // 不为0：将id最大的数据设置为默认地址
		    			Integer maxId = getMaxId(uid);
		    			setDefault(maxId);
		    		}
		    	}
		    } else {
		        // 归属错误：抛出异常AddressAccessException
		    	throw new AddressAccessException(
		    		"尝试删除的收货地址数据归属错误！");
		    }
		} else {
		    // 不存在：抛出异常AddressNotFoundException
			throw new AddressNotFoundException(
				"尝试删除的收货地址数据不存在！");
		}
	}

### 3.4.3. 删除收货地址-控制器层

步骤1：是否需要处理新的异常？有：`DeleteDataException`，所以，需要在`BaseController`中进行处理。

步骤2：设计请求：

	请求路径：/address/delete.do
	请求类型：不限
	请求参数：id(*)
	响应方式：ResponseResult<Void>
	是否拦截：是，登录拦截，无需修改配置

则处理请求的方法：

	@RequestMapping("/delete.do")
	@ResponseBody
	public ResponseResult<Void> delete(
			@RequestParam("id") Integer id,
			HttpSession session) {
		Integer uid = getUidFromSession(session);
		addressService.delete(id, uid);
		return new ResponseResult<Void>();
	}

## 4. 主页热销排行

#### 4.1. 主页热销排行-持久层

为了使得查询商品列表的功能可以适用于多处，所以，在设计时，使用了更多参数，使得功能的运用可以更加灵活，在`GoodsMapper`接口中声明的抽象方法是：

	List<Goods> getList(
		@Param("where") String where,
		@Param("orderBy") String orderBy,
		@Param("offset") Integer offset,
		@Param("count") Integer count
	);

对应的SQL映射：

	SELECT 
		id, title, image, price
	FROM 
		t_goods
	<if test="where != null">
	WHERE 
		${where}
	</if>
	<if test="orderBy != null">
	ORDER BY 
		${orderBy}
	</if>
	<if test="offset != null">
	LIMIT 
		#{offset}, #{count}
	</if>

**关于#{}和${}**

在MyBatis的映射中，使用`#{}`表示的变量，是以前学习JDBC阶段使用问号(`?`)可以表示的内容，在处理过程中，会使用预编译的方式来进行处理，并且，无视数据类型，所以，在编写SQL语句时，即使某个变量的值是字符串类型的，也不需要写成`username='#{username}'`这种在两端添加单引号的语法。

使用`${}`表示的变量，是通过字符串的拼接形成的SQL语句，所以，如果使用它来表示字符串或其它例如时间等格式，可能存在两端的符号的问题。

一般，值都使用`#{}`格式的变量，这种格式无法表示SQL语句中的某个部分，例如包含字段名等等，对于这种需求，就需要使用`${}`格式的变量。

注意：由于使用`${}`格式的变量，最终在处理时只是单纯的拼接SQL语句，所以，可能存在SQL注入的风险！通常，关键部分的数据，是不允许提交相关特殊字符的，所以，如果对参数的字符时行了过滤，或者例如密码都是经过摘要运算加密过的，其中并不包括单引号(`'`)，就不会出现SQL注入的问题，所以，也不用太过于紧张关于SQL注入的问题！

	SELECT * FROM t_user WHERE
		username='chengheng' AND password='1234'

	SELECT * FROM t_user WHERE
		username='chengheng' AND password='1' OR '1'='1'

	username : chengheng
	password : 1' OR '1'='1

#### 4.2. 主页热销排行-业务层

创建`cn.jacob.store.service.IGoodsService`接口，声明抽象方法：

	List<Goods> getHotGoodsList();

创建`cn.jacob.store.service.GoodsServiceImpl`实现类，实现以上接口，添加`@Service("goodsService")`，声明`@Autowired private GoodsMapper goodsMapper`，然后，声明与持久层相同的方法，使用私有权限，直接调用即可：

	private List<Goods> getList(String where, String orderBy, Integer offset, Integer count) {
		return goodsMapper.getList(where, orderBy, offset, count);
	}

关于接口中抽象方法的实现：

	public List<Goods> getHotGoodsList() {
		return getList(null, "priority DESC", 0, 4);
	}

完成后，执行测试。









## 关于导入数据

进入MySQL控制台，通过`source d:/t_goods.sql`语法导入。

检查：

	SELECT id, title FROM t_goods LIMIT 0, 10;

	SELECT id, name FROM t_goods_category LIMIT 0, 10;

自带电脑的同学：使用工具

基于Linux的同学：新建记事本，粘贴SQL脚本，然后导入自行创建的记事本！不要执行`set names gbk;`，如果已经执行，则需要再次执行`set names utf8;`

## 4. 主页热销排行

#### 4.3. 主页热销排行-控制器层

分析请求：

	请求路径：/goods/hot_list.do
	请求类型：GET
	请求参数：无
	响应方式：ResponseResult<List<Goods>>
	是否拦截：否

则创建控制器类，完成基本步骤，并添加处理请求的方法：

	@RequestMapping("/hot_list.do")
	@ResponseBody
	public ResponseResult<List<Goods>> getHotList() {
		ResponseResult<List<Goods>> rr
			= new ResponseResult<List<Goods>>();
		List<Goods> list = goodsService.getHotGoodsList();
		rr.setData(list);
		return rr;
	}

#### 4.4. 主页热销排行-前端页面

当页面刚刚打开时（`$(document).ready()`）发出AJAX请求，并获取数据，最后显示在列表中（复制现有的HTML代码并使用数据进行替换）。

	<script type="text/javascript">
	$(document).ready(function() {
		var url = "../goods/hot_list.do";
		$.ajax({
			"url": url,
			"type": "GET",
			"dataType": "json",
			"success": function(json) {
				$("#hot-list").empty();
				
				var list = json.data;
				console.log("热销的4件商品：")
				for (var i = 0; i < list.length; i++) {
					console.log(list[i].title);
					
					var html = '<div class="col-md-12">'
						+ '<div class="col-md-9"><a href="product.html">#{goodsTitle}</a></div>'
						+ '<div class="col-md-3"><img src="..#{goodsImage}collect.png" height="50" /></div>'
						+ '</div>';
						
					html = html.replace(/#{goodsTitle}/g, list[i].title);
					html = html.replace(/#{goodsImage}/g, list[i].image);
					
					$("#hot-list").append(html);
				}
			}
		});
	});
	</script>

## 5. 显示商品详情

### 5.1. 显示商品详情-持久层

虽然原有的持久层中的`getList()`可以完成**根据id查询商品数据**的功能，但是，它查询的字段较少，不足以满足**显示商品详情**的需求，如果，一定去修改原有的`getList()`查询时的字段列表，又会导致该功能应用于**查询列表**时会查询更多的不必要的字段，会出现资源的浪费，所以，原有的`getList()`只用于各种列表的查询，而不通过它来实现详情的查询。

在持久层接口中添加新的抽象方法：

	Goods findGoodsById(String id);

然后，配置它的映射：

	SELECT 
		id, 
		category_id	AS	categoryId,
		item_type		AS	itemType,
		title,
		sell_point		AS	sellPoint,
		price,
		num,
		barcode,
		image,
		status,
		priority
	FROM 
		t_goods
	WHERE 
		id=?

### 5.2. 显示商品详情-业务层

该功能没有业务。

业务层公有的、用于组织业务的方法：

	public Goods getGoodsById(String id) { }

私有的、用于实现功能的方法：

	private Goods findGoodsById(String id);

### 5.3. 显示商品详情-控制器层

分析请求：

	请求路径：/goods/details.do
	请求类型：GET
	请求参数：id(*)
	响应方式：ResponseResult<Goods>
	是否拦截：否

则创建控制器类，完成基本步骤，并添加处理请求的方法：

	@RequestMapping("/details.do")
	@ResponseBody
	public ResponseResult<Goods> getDetails(
		@RequestParam("id") String id) {
		Goods goods = goodsService.getGoodsById(id);
		ResponseResult<Goods> rr
			= new ResponseResult<Goods>();
		rr.setData(goods);
		return rr;
	}

### 5.4. 显示商品详情-前端页面

前端页面的主要任务是：获取URL中的id，根据id查询数据，并将数据显示在界面中，此操作应该在页面打开时即执行（`#(document).ready()`），显示数据时，只需要将数据显示到对应的HTML标签中即可(`$("#tag").html(value)`)。

## 6. 购物车管理

### 6.1. 将商品添加到购物车

#### 6.1.1. 将商品添加到购物车-持久层

先确定购物车的数据表：

	CREATE TABLE t_cart (
		id INT AUTO_INCREMENT,
		uid INT NOT NULL,
		goods_id VARCHAR(200) NOT NULL,
		goods_num INT NOT NULL,
		created_time DATETIME,
		created_user VARCHAR(20),
		modified_time DATETIME,
		modified_user VARCHAR(20),
		PRIMARY KEY(id)
	) DEFAULT CHARSET=UTF8;

然后创建对应的实体类`cn.jacob.store.entity.Cart`，继承自`BaseEntity`。

创建持久层接口`cn.jacob.store.mapper.CartMapper`，并添加抽象方法：

	// 插入数据
	Integer insert(Cart cart);

	// 查询
	Cart findCartByUidAndGoodsId(
		@Param("uid") Integer uid, 
		@Param("goodsId") String goodsId);

	// 修改数量
	Integer updateGoodsNum(
		@Param("id") Integer id, 
		@Param("goodsNum") Integer goodsNum);

最后，配置以上抽象方法的映射，SQL语句大致是：

	INSERT INTO t_cart (uid, goods_id, goods_num) VALUES (?, ?, ?)

	SELECT id, goods_num FROM t_cart WHERE goods_id=? AND uid=?

	UPDATE t_cart SET goods_num=? WHERE id=?

#### 6.1.2. 将商品添加到购物车-业务层

创建业务层接口，添加抽象方法：

	void addToCart(Cart cart);

然后，创建业务层实现类，按常规步骤编写，并重写其中的抽象方法：

	public void addToCart(Cart cart) {
		// 根据cart参数中封装的uid和goodsId执行查询
		// 判断结果是否为null
			// 是：该用户此前没有添加该商品，则执行插入数据
			// 否：该用户已经添加该商品，获取原有数量
			// 从cart参数中获取此次的增量，并计算得到新的数量
			// 更新商品数量
	}





### 在HTML中获取URL中的参数

核心是通过Javascript中的`location.search`可以获取URL中从`?`开始，右侧的所有内容，例如URL是`http://localhost:8080/jacobStore/web/product.html?from=Beijing&id=9527&user=Jack`，则`location.search`的值是`?from=Beijing&id=9527&user=Jack`。

后续，根据`location.search`的结果进行分析，即可得到其中某些参数的值。

如果只需要获取某个指定名称的参数值，例如获取`id`值，或者`user`的值，推荐使用正则表达式来匹配，从而获取属性值，通常，基于jQuery进行封装：

	(function ($) {
		  $.getUrlParam = function (name) {
		   var reg = new RegExp("(^|&)" + name + "=([^&]*)(&|$)");
		   var r = window.location.search.substr(1).match(reg);
		   if (r != null) return unescape(r[2]); return null;
		  }
	})(jQuery);

经过以上代码后，可以通过`$.getUrlParam("id")`获取URL中名为`id`的属性的值，通过`$.getUrlParam("user")`获取URL中名为`user`的属性的值，使用这样的做法，在URL中的多个属性中，各属性并不区分前后顺序。

**注意：该函数只能获取指定名称的第1个参数值！即URL中的参数包含id=666&id=888&id=999时，通过以上函数，只能获取到666这1个值。**

#### 6.1.4. 将商品添加到购物车-前端页面

服务器端的控制器所需要的请求参数包括：`goods_id`、`goods_num`，应该在商品详情页点击“加入购物车”时发出请求，并提交这2个参数即可，如果用户没有登录，则还需要先登录！

商品id在加载页面时，已经从URL中获取了，所以，将此前的商品id声明为全局变量，由于加载页面时已经完成赋值，所以，在“加入购物车”时，直接使用全局变量的id即可用于表示商品的id。

除了商品id以外，还需要提交到服务器端的数据就只有商品数量了，没有必要专门添加一个`<form>`再通过`#("form-id").serialize()`来提交，直接拼接出`goods_id=xx&goods_num=xx`参数即可。

另外，此次操作是需要登录的，所以，在处理AJAX时，还要添加`error`配置，以免被服务器端的拦截器拦截后响应结果是重定向。

	// 点击“加入购物车”时
	$("#btn-add-to-cart").click(function() {
		var url = "../cart/add.do";
		var goodsNum = $("#num").val();
		var data = "goods_id=" + id 
				+ "&goods_num=" + goodsNum;
		console.log(data);
		$.ajax({
			"url": url,
			"data": data,
			"type": "POST",
			"dataType": "json",
			"success": function(json) {
				if (json.state == 200) {
					alert("操作成功！");
				} else {
					alert("操作失败！" + json.message);
				}
			},
			"error": function(xhr) {
				console.log("响应码：" + xhr.status);
				alert("您的登录信息已过期，请重新登录！");
				location.href = "login.html";
			}
		});
	});

### 6.2. 显示购物车列表

#### 6.2.1. 显示购物车列表-持久层

通常，为了规范的设计数据表，所以，可能在数据库存储了一些外链，即其它表中的id，而并没有存储实际的数据，并且，实体类都是与数据表对应的，所以，涉及多张表的查询时，实体类并不适合作为查询的结果类型，则需要另创建VO类来表示查询结果。

购物车数据就是存在关键查询的，所以，需要查询的结果能直接显示出所需要显示的数据，则需要有对应的VO类，则创建`cn.jacob.store.vo.CartVO`类：

	public class CartVO implements Serializable {

		private static final long serialVersionUID = -4226267978903049502L;

		private Integer cartId;
		private Integer uid;
		private String goodsId;
		private String goodsTitle;
		private String goodsImage;
		private Long goodsPrice;
		private Integer goodsNum;

		// SET/GET方法
	}

关于VO类的属性设计，可以根据查询、显示的需求来决定。

然后，在持久层接口中声明抽象方法时，查询结果的类型就是VO类的类型：

	List<CartVO> getList(Integer uid);

需要执行的SQL语句：

	SELECT 
		c.id	AS	cartId,
		c.uid,
		c.goods_id	AS	goodsId,
		c.goods_num	AS	goodsNum,
		g.title	AS	goodsTitle,
		g.image	AS	goodsImage,
		g.price	AS	goodsPrice
	FROM 
		t_cart AS c
	INNER JOIN
		t_goods AS g
	ON 
		c.goods_id=g.id
	WHERE
		c.uid=#{uid};

以上查询，也可以通过`SELECT xx FROM 表1,表2 WHERE 表1.xx=表2.xx`此类的语法来实现，但是，不推荐这种语法。

#### 6.2.2. 显示购物车列表-业务层

通常，查询并直接显示的功能，没有太多业务逻辑需要设计，所以，业务层的设计相对比较简单，首先，在接口中声明公有的、组织业务的方法：

	List<CartVO> getCartListByUid(Integer uid);

然后，在实现类实现以上方法，且，实现类应该添加私有的、执行数据访问的方法：

	private List<CartVO> getList(Integer uid) {
		return cartMapper.getList(uid);
	}

	public List<CartVO> getCartListByUid(Integer uid) {
		return getList(uid);
	}

#### 6.2.3. 显示购物车列表-控制器层

在控制器类中添加处理请求的方法：

	@RequestMapping("/list.do")
	@ResponseBody
	public ResponseResult<List<CartVO>> getCartListByUid(
		HttpSession session) {
		// 获取uid
		// 执行
		// 创建返回值对象
		// 封装数据
		// 返回
	}

#### 6.2.4. 显示购物车列表-前端页面

显示数据的前端页面是`cart.html`。

由于该页面是必须登录才可以访问的，所以，无需调整`HtmlAccessFilter`。

在页面刚刚加载时（`$(document).ready()`）就应该请求数据列表，先请求到所需的数据，并显示在控制台，表示测试。

如果能够成功获取数据，则找出`cart.html`中显示列表的HTML代码，声明为Javascript中的模版，并将其中需要替换的内容使用占位符表示，在遍历查询到的数据结果时，替换占位符，并添加到列表的容器对象中，即可完成显示。

以上流程，可参考`index.html`中的热销列表。

### 6.3. 修改购物车商品数量

#### 6.3.1. 修改购物车商品数量-持久层

由于持久层中已经存在：

	Integer updateGoodsNum(
		@Param("id") Integer id, 
		@Param("goodsNum") Integer goodsNum);

通过该方法即可实现商品数量的修改，所以，本次无须重新开发修改的功能。

由于后续功能需要**根据购物车数据id进行查询**的功能，所以，在持久层添加新的抽象方法：

	Cart findCartById(Integer id);

然后配置以上方法的映射。

#### 6.3.2. 修改购物车商品数量-业务层

在修改商品数量时，可能抛出2种新的异常：`CartNotFoundException`、`GoodsNumLimitException`，所以，需要创建这2个新的异常类。

可以在业务层接口中添加2个新的抽象方法：

**方法1：将商品数量+1**

购物车数据id应该在用户提交请求时，由用户提交。

用户提交的商品数量只是增量而已，而不是运算得到的新数量，所以，应该先根据购物车数据id查询数据，获取原数量，结合增量，得到新数量。

执行`updateGoodsNum(购物车数据id，商品新数量)`

所以，在业务层接口中添加抽象方法：

	void addNum(Integer id);

在实现类中：

	private Cart findCartById(Integer id) {
		return cartMapper.findCartById(id);
	}

	public void addNum(Integer id) {
		Cart cart = findCartById(id);
		if (cart == null) {
			throw new CartNotFoundException(
				"尝试访问的购物车数据不存在！");
		}
		Integer num = cart.getGoodsNum() + 1;
		updateGoodsNum(id, num);
	}

**方法2：将商品数量-1**

实现思路与方法1基本相同，在业务层接口中添加抽象方法：

	void reduceNum(Integer id);

在实现类中：

	public void reduceNum(Integer id) {
		Cart cart = findCartById(id);
		if (cart == null) {
			throw new CartNotFoundException(
				"尝试访问的购物车数据不存在！");
		}
		if(cart.getGoodsNum() <= 1) {
			throw new GoodsNumLimitException(
				"尝试修改的购物车数据的商品数量招出限制！");
		}
		Integer num = cart.getGoodsNum() - 1;
		updateGoodsNum(id, num);
	}

#### 6.3.3. 修改购物车商品数量-控制器层

由于业务层抛出了新的异常，应该在`BaseController`中对这2种新的异常进行处理。

在控制器层添加2个方法：

	@RequestMapping("add_num.do")
	@ResponseBody
	public ResponseResult<Void> addGoodsNum(
		@RequestParam("id") Integer id) {
		cartService.addNum(id);
		return new ResponseResult<Void>();
	}

	@RequestMapping("reduce_num.do")
	@ResponseBody
	public ResponseResult<Void> reduceGoodsNum(
		@RequestParam("id") Integer id) {
		cartService.reduceNum(id);
		return new ResponseResult<Void>();
	}

完成后，通过`http://localhost:8080/jacobStore/cart/add_num.do?id=10`这类URL在浏览器中进行测试。

#### 6.3.4. 修改购物车商品数量-前端页面

首先，需要为加号、减号按钮绑定事件，在AJAX获取到购物车数据，生成HTML代码时，配置`onclick="add(#{cartId})"`：

	<input type="button" value="+" class="num-btn" onclick="add(#{cartId})" />

由于需要访问到显示商品数量的输入框，需要为输入框添加id：

	<input id="goods-num-#{cartId}" type="text" size="2" readonly="readonly" class="num-text" value="#{goodsNum}">

且右侧的`span`标签中还需要显示每项商品的总价，页面加载时、加减数量时都需要显示总价，则这个标签也需要id：

	<span id="goods-total-#{cartId}">#{goodsTotalPrice}</span>

在加载页面时显示每项商品的总价：

	html = html.replace(/#{goodsTotalPrice}/g, list[i].goodsPrice * list[i].goodsNum);

然后，编写“增加数量”的函数：

	function add(id){
		// alert("add:" + id);
		var url = "../cart/add_num.do";
		var data = "id=" + id;
		$.ajax({
			"url": url,
			"data": data,
			"type": "GET",
			"dataType": "json",
			"success": function(json) {
				if (json.state == 200) {
					// 输入框中的数量：取出原数量，并+1
					var n = parseInt($("#goods-num-" + id).val()) + 1;
					$("#goods-num-" + id).val(n);
					// 显示单项商品的总价
					var p = parseInt($("#goods-price-" + id).html());
					var total = p * n;
					$("#goods-total-" + id).html(total);
				} else {
					alert("操作失败！" + json.message)
				}
			},
			"error": function(xhr) {
				console.log("响应码：" + xhr.status);
				alert("您的登录信息已过期，请重新登录！");
				location.href = "login.html";
			}
		});
	}

关于“减少数量”，做法类似，则课后自行完成！

### 7. 显示确认订单

将由“购物车列表”页的勾选，并提交后，显示“确认订单”，需要的：

1. 在购物车列表页：约104行，为`<form>`标签添加`method`和`action`属性：

	<form method="get" action="orderConfirm.html" role="form">

2. 在购物车列表页，“提交”按钮的类型应该是`type="submit"`

3. 在生成列表项时，每个`<input type="checkbox" ... />`都必须配置`name`和`value`，且`value`值应该是每条数据的id，使用占位符，后续会被替换：
	```
	<input name="cart_id" value="#{cartId}" type="checkbox" class="ckitem" />
	```

**需下载新的静态页面V2.0，解压后，覆盖到项目中之前，先删除js/product.js文件！**

在“确认订单”页面，需要使用到的功能有：

1. 获取当前用户的所有收货地址数据，以显示在`<select>`下拉列表中；

2. 获取选中的`cart_id`对应的购物车数据，显示在需要确认的商品列表中。

**功能1：显示收货地址列表**

此前，已经完成了“获取当前登录的用户的收货地址列表”功能，在`AddressController`中已经设计了`/address/list.do`请求路径，可以通过这个请求路径获取收货地址列表，则无须重新开发，直接请求这个路径，获取数据即可！

当前页面（确认订单页面）是必须登录的，所以，无须修改`HtmlAccessFilter`中的白名单。

**功能2：显示选中的购物车数据列表**

需要“根据多个id查询购物车中的数据的列表”功能，则应该先在持久层开发该功能：

	List<CartVO> getListByIds(Integer[] ids);

	<select id="getListByIds" resultType="xx.xx.xx.CartVO">
		SELECT 
			c.id	AS	cartId,
			c.uid,
			c.goods_id	AS	goodsId,
			c.goods_num	AS	goodsNum,
			g.title	AS	goodsTitle,
			g.image	AS	goodsImage,
			g.price	AS	goodsPrice
		FROM 
			t_cart AS c
		INNER JOIN
			t_goods AS g
		ON 
			c.goods_id=g.id
		WHERE
			c.id IN (
			<foreach collection="array" 
				item="id" separator=",">
			#{id}
			</foreach>
			)
	</select>

后续，参考此前的模式完成业务层和控制器层即可。

然后，在前端页面中，当页面加载完成时，获取URL中的`cart_id`的值，并组织成数组，然后再次发出AJAX请求获取数据。

关于`cart_id`的获取，首先，不可以通过`$.getUrlParam()`函数去获取，因为，这个函数只能获取多个同名参数中的第1个参数值！对于参数为`cart_id=9&cart_id=10&cart_id=11`此类URL，只能自行编写程序来获取：

	// 获取网址中的参数部分，不需要问号，所以，调用substring(1)进行截取
	var params = location.search.substring(1);
	// 组织本次需要提交的参数
	var data = "";
	// 将当前URL中的参数拆成数组
	var paramArray = params.split("&");
	// 遍历数组 
	for (var i = 0; i< paramArray.length; i++) {
		// 将每一组参数(cart_id=8)再拆成数组
		var arr = paramArray[i].split("=");
		// 判断参数名称
		if (arr[0] == "cart_id") {
			// 参数名为cart_id，则获取值
			data += "&ids=" + arr[1];
		}
	}
	data = data.substring(1);

处理好参数后，则发出请求，获取结果，显示，完成。

## 订单表

	CREATE TABLE t_order (
		id INT AUTO_INCREMENT,
		uid INT NOT NULL,
		recv_name
		recv_phone
		recv_district
		recv_address
		recv_zip
		pay
		status
		order_time	
		pay_time
		// 4个日志
		PRIMARY KEY(id)
	) DEFAULT CHARSET=UTF8;

	CREATE TABLE t_order_item (
		id INT AUTO_INCREMENT,
		order_id INT NOT NULL,
		goods_id
		goods_image
		goods_title
		goods_price
		goods_num
		// 4个日志
		PRIMARY KEY(id)
	) DEFAULT CHARSET=UTF8;

## 8. 创建订单

### 8.1. 创建订单-持久层

**数据表**

订单的数据中，存在“1个订单中可以有多样商品”的关系，即“订单”与“订单中的商品的种类”是1对多的关系，所以，只使用1张数据表是无法存储订单相关信息的，就需要“订单表”和“订单商品表”这2张数据表来完成存储！

订单中的某些数据一旦产生，将不会随着后续数据的变化而再次调整，例如价格，下单时确定了价格以后，无论后续商品的价格如何调整，此订单中的商品价格是不会再次发生变化的，所以，在存储时，应该把价格直接存储在订单相关的表中，而不是通过商品的id关联到商品表再查询！此类的数据还包括：收货人的相关信息、商品的完整信息等。

订单的总价格应该是将汇总数据直接存储的，在实际应用中，总价格不一定与商品数量和单价对应， 因为还可能存在各种优惠减免的情况。

创建数据表：

	CREATE TABLE t_order (
		id INT AUTO_INCREMENT,
		uid INT NOT NULL,
		recv_name VARCHAR(16) NOT NULL,
		recv_phone VARCHAR(20) NOT NULL,
		recv_district VARCHAR(30) NOT NULL,
		recv_address  VARCHAR(50) NOT NULL,
		recv_zip CHAR(6),
		pay BIGINT(20) NOT NULL,
		status INT NOT NULL,
		order_time DATETIME NOT NULL,
		pay_time DATETIME,
		created_time DATETIME,
		created_user VARCHAR(20),
		modified_time DATETIME,
		modified_user VARCHAR(20),
		PRIMARY KEY(id)
	) DEFAULT CHARSET=UTF8;

	CREATE TABLE t_order_item (
		id INT AUTO_INCREMENT,
		order_id INT NOT NULL,
		goods_id VARCHAR(200) NOT NULL,
		goods_image VARCHAR(500) NOT NULL,
		goods_title VARCHAR(100) NOT NULL,
		goods_price BIGINT(20) NOT NULL,
		goods_num INT NOT NULL,
		created_time DATETIME,
		created_user VARCHAR(20),
		modified_time DATETIME,
		modified_user VARCHAR(20),
		PRIMARY KEY(id)
	) DEFAULT CHARSET=UTF8;

**实体类**

实体类是与数据表一一对应的，所以，与订单相关的数据表有2张，则实体类也应该是2个。

当然，这样的实体类可能不便于表示数据，后续可以通过VO类来使用！

**接口与抽象方法**

通常，每张数据表的操作都对应了持久层中的1个接口，而此次的订单数据处理时，“订单商品表”通常不会单独访问，而是随着“订单表”一起进行数据操作，例如：创建订单时，一并创建订单商品中的数据，或，删除订单时，也应该删除订单商品中的数据……所以，没有必要创建`OrderItemMapper.java`，原本希望设计在这个接口中的方法直接设计在`OrderMapper.java`中就可以了。

所以，创建`cn.jacob.store.mapper.OrderMapper`接口，声明抽象方法：

	// 创建订单
	Integer insertOrder(Order order);

	// 创建订单商品
	Integer insertOrderItem(OrderItem orderItem);

注意：每个抽象方法应该只对应1条需要执行的SQL指令，尽管“创建订单”应该至少有2条SQL指令，但是，功能的组织应该在业务层中完成！

**XML映射**

复制并得到`OrderMapper.xml`，配置以上2个抽象方法的映射。

### 8.2. 创建订单-业务层

**前序任务**

实现“根据收货地址id，查询收货地址详情”的功能，其业务方法为：

	Address getAddressById(Integer id);

**创建订单**

关于“创建订单”，可以由用户提供的数据就是业务层方法的参数，有：收货地址id，若干个购物车数据id，及当前登录的用户的id。则，业务中的方法：

	void createOrder(Integer uid, Integer addressId, Integer[] cartIds);

然后，创建实现类`cn.jacob.store.service.impl.OrderServiceImpl`：
	
	@Autowired private IAddressService addressService;
	@Autowired private ICartService cartService;

	@Transactional
	public void createOrder(Integer uid, Integer addressId, Integer[] cartIds) {
		// 获取当前时间
		Date now = new Date();
		
		// 根据cartIds获取商品相关数据
		List<CartVO> carts = cartService.getListByIds(uid, cartIds);
		// 计算总金额
		Long pay = 0L;
		for (CartVO cartVO : carts) {
			pay += cartVO.getGoodsPrice() * cartVO.getGoodsNum();
		}

		// 根据addressId获取收货地址数据
		Address address = addressService.getAddressById(addressId);
		// 准备插入订单数据
		Order order = new Order();
		order.setUid(uid);
		order.setRecvName(address.getRecvName());
		// 类似，封装收货数据
		order.setStatus(0); // 0-未支付
		order.setOrderTime(now);
		order.setPayTime(null);
		order.setPay(pay);

		// 执行：插入订单数据
		insertOrder(order);

		// 执行：插入订单商品数据
		for (CartVO cartVO : carts) {
			OrderItem item = new OrderItem();
			item.setOrderId(order.getId());
			item.setGoodsId(cartVO.getGoodsId());
			// 类似，封装商品数据
			insertOrderItem(item);
		}

		// TODO 根据参数Integer[] cartIds读取到的goods_id和goods_num，更新t_goods表中商品的库存

		// TODO 根据参数Integer[] cartIds删除购物车中对应的数据
	}

	private void insertOrder(Order order) {
	}

	private void insertOrderItem(OrderItem orderItem) {
	}

### 8.3. 创建订单-控制器层

创建`cn.jacob.store.controller.OrderController`类，添加处理请求的方法：

	@RequestMapping(value="/create.do", method=RequestMethod.POST)
	@ResponseBody
	public ResponseResult<Void> createOrder(
		@RequestParam("address_id") Integer addressId,
		@RequestParam("cart_ids") Integer[] cartIds,
		HttpSession session) {
		// 获取uid
		// 调用业务层实现功能
		// 返回
	}


### 8.4. 创建订单-前端页面

前端页面使用`<form>`表单和`<input type="submit" ... />`提交按钮即可提交数据，其中，`Integer[] cartIds`可以使用`<input type="hidden" name="cartIds" value="xx" />`隐藏域来提交。

## 查询订单

由于一个完整的订单数据需要“订单表”和“订单商品表”中的数据共同构成，且订单表中的数据与订单商品表中的数据是1对多的关系，在查询时，需要使用关联查询：

	SELECT
		*
	FROM 
		t_order
	INNER JOIN
		t_order_item
	ON
		t_order.id = t_order_item.order_id
	WHERE
		t_order.id=1;

并且，实体类无法表示查询结果，则应该创建VO类来表示查询结果：

	public class OrderVO implements Serializable {
	
		private static final long serialVersionUID = 310521494455105831L;
	
		private Integer id;
		private Integer uid;
		private String recvName;
		private String recvPhone;
		private String recvDistrict;
		private String recvAddress;
		private String recvZip;
		private Long pay;
		private Integer status;
		private Date orderTime;
		private Date payTime;
		private List<OrderItem> orderItems;
		
		// ...

	}

并且，在查询时，必须配置`<resultMap>`来确定1对多的数据结果将如何存储到VO类的对象中：

	<resultMap id="OrderMap" 
		type="cn.jacob.store.vo.OrderVO">
		<id column="oid" property="id" />
		<result column="uid" property="uid" />
		<result column="recv_name" property="recvName" />
		<result column="recv_phone" property="recvPhone" />
		<result column="recv_district" property="recvDistrict" />
		<result column="recv_address" property="recvAddress" />
		<result column="recv_zip" property="recvZip" />
		<result column="pay" property="pay" />
		<result column="status" property="status" />
		<result column="order_time" property="orderTime" />
		<result column="pay_time" property="payTime" />
		<collection property="orderItems"
			ofType="cn.jacob.store.entity.OrderItem">
			<id column="oiid" property="id" />
			<result column="order_id" property="orderId" />
			<result column="goods_id" property="goodsId" />
			<result column="goods_title" property="goodsTitle" />
			<result column="goods_image" property="goodsImage" />
			<result column="goods_price" property="goodsPrice" />
			<result column="goods_num" property="goodsNum" />
		</collection>
	</resultMap>

	<!-- 根据订单id查询订单详情 -->
	<!-- OrderVO getOrderById(Integer orderId) -->
	<select id="getOrderById"
		resultMap="OrderMap">
		SELECT
			o.id AS oid,
			o.uid,
			recv_name, recv_phone,
			recv_district, recv_address,
			recv_zip,
			pay, status,
			order_time, pay_time,
			oi.id AS oiid,
			order_id,
			goods_id,
			goods_title, goods_image,
			goods_price, goods_num
		FROM 
			t_order AS o
		INNER JOIN
			t_order_item AS oi
		ON
			o.id = oi.order_id
		WHERE
			o.id=#{orderId};
	</select>

**如果对<resultMap>的配置不熟悉，可参考MYBATIS阶段DAY02的笔记中的图示。**

测试以上查询的结果例如：

	OrderVO [
		id=1, uid=3, 
		recvName=小王女士, 
		recvPhone=13800138001, 
		recvDistrict=浙江省, 舟山市, 嵊泗县, 
		recvAddress=高新小区, 
		recvZip=, 
		pay=410310, 
		status=0, 
		orderTime=Thu Dec 13 11:03:33 CST 2018, 
		payTime=null, 
		orderItems=[
			OrderItem [id=1, orderId=1, goodsId=10000042, goodsImage=/images/portal/21ThinkPad_New_S1/, goodsTitle=联想ThinkPad New S1（01CD） i5 6代 红色, goodsPrice=4399, goodsNum=60], 
	
			OrderItem [id=2, orderId=1, goodsId=10000022, goodsImage=/images/portal/13LenovoIdeaPad310_black/, goodsTitle=联想（Lenovo）IdeaPad310经典版黑色, goodsPrice=5119, goodsNum=20], 
	
			OrderItem [id=3, orderId=1, goodsId=100000424, goodsImage=/images/portal/21ThinkPad_New_S1/, goodsTitle=联想ThinkPad New S1（01CD） i5 6代 蓝色, goodsPrice=4399, goodsNum=10]
		]
	]

## Spring AOP

Spring AOP指的是“面向切面的编程”，它将数据的处理流程比喻成一条线，例如：控制器 > 业务层 > 持久层，每个功能的数据处理都是使用相同的处理流程，在这个过程中，可能有某些任务是公共的，即无论处理哪项数据的功能，都需要执行相同的任务，那么，面向切面的意思就是在这个过程中产生一个切入点，并确定切入点需要执行的代码，后续，每个数据处理流程都会执行相同的代码，就是面向切面的编程了。

AOP并不是Spring独有的特性！只是Spring框架提供了简便的实现AOP的编码方式。

关于使用，首先，需要添加相关依赖：

	<!-- AOP -->
	<dependency>
		<groupId>aspectj</groupId>
		<artifactId>aspectj-tools</artifactId>
		<version>1.0.6</version>
	</dependency>

	<dependency>
		<groupId>aspectj</groupId>
		<artifactId>aspectjweaver</artifactId>
		<version>1.5.4</version>
	</dependency>

**由于使用的是基于Spring的AOP，所以，还需要spring-webmvc依赖，如果项目已经应用Spring框架，则无需重复添加spring-webmvc依赖。**

然后，需要在Spring的配置文件中开启AOP的自动代理：

	<!-- 开启自动代理 -->
	<aop:aspectj-autoproxy />

然后，编写切面类，实现切面效果：

	@Component
	@Aspect
	public class TimeElapsedAspect {
	
		private long startTime;
		
		@Around("execution(* cn.jacob.store.service.impl.*.*(..))")
		public Object around(ProceedingJoinPoint pjp) throws Throwable {
			// 执行前序任务
			doBefore();
			
			// 调用原本应该执行的方法
			Object result = pjp.proceed();
			
			// 执行后续任务
			doAfter();
			
			// 返回原本应该执行的方法的返回值
			return result;
		}
		
		public void doBefore() {
			System.out.println("TimeElapsedAspect.doBefore()");
			startTime = System.currentTimeMillis();
		}
		
		public void doAfter() {
			long endTime = System.currentTimeMillis();
			long elapsed = endTime - startTime;
			System.out.println("TimeElapsedAspect.doAfter() : " + elapsed);
		}
		
	}

以上代码中，`@Around("execution(* cn.jacob.store.service.impl.*.*(..))")`注解中的配置，表示**无论是哪种返回值，只要是在cn.jacob.store.service.impl包下的任类（第1个星号）中的任何方法（第2个星号），且无论是什么参数（两个小数点）**，都满足切面的执行前提，所以，后续，在执行这个包中的任何类中的任何业务方法时，都会按照`@Around`对应的方法流程来进行处理！















	@RequestMapping(value="/handle_login.do", 
			method=RequestMethod.POST)
	@ResponseBody
	public ResponseResult handleLogin(
			String username, String password, 
			HttpSession session) {
		// 声明返回值
		ResponseResult rr;
		try {
			// 调用业务层对象的login()方法，并获取返回值
			User result = userService.login(username, password);
			// 在session中封装必要的数据
			session.setAttribute("uid", result.getId());
			session.setAttribute("username", result.getUsername());
			// 在返回值对象中封装state值为1
			rr = new ResponseResult(1);
		} catch (UserNotFoundException e) {
			// 在返回值对象中封装state值为-1
			// 在返回值对象中封装message值为e.getMessage
			rr = new ResponseResult(-1, e);
		} catch (PasswordNotMatchException e) {
			// 在返回值对象中封装state值为-2
			// 在返回值对象中封装message值为e.getMessage
			rr = new ResponseResult(-2, e);
		}
		// 返回
		return rr;
	}

以上代码基于在`ResponseResult`中添加新的构造方法：

	public ResponseResult() {
		super();
	}

	public ResponseResult(Integer state) {
		super();
		this.state = state;
	}

	public ResponseResult(Integer state, Throwable throwable) {
		super();
		this.state = state;
		this.message = throwable.getMessage();
	}

全部完成后，通过`http://localhost:8080/SSM-AJAX-01-SAMPLE/user/handle_login.do?username=mybatis&password=1234`，如果测试无误，将处理请求的方法限制为：只允许提交POST请求。

### 1.9. 登录-前端界面

	<script type="text/javascript">
	$("#btn_login").click(function() {
		var url = "user/handle_login.do";
		var data = $("#login_form").serialize(); // 根据控件的name和value拼接出参数数据
		$.ajax({
			"url": url,
			"data": data,
			"type": "POST",
			"dataType": "json",
			"success": function(json) {
				if (json.state == 1) {
					alert("登录成功！");
				} else if (json.state == -1) {
					alert("登录失败！" + json.message);
				} else if (json.state == -2) {
					alert("登录失败！" + json.message);
				}
			}
		});
	});
	</script>

＃商城
## 1.数据分析

通过观察静态页面，当前项目中至少包括以下类型的数据：商品，商品分类，用户 ，收货地址，购物车，收藏，订单。

关于以上数据，处理的顺序可以是：用户，收货地址，商品分类，商品，购物车，收藏，订单。

每项数据的处理都应该是：增，查，删，改。

每个功能的处理都应该是：持久层，业务层，控制器层，前端界面。

## 2. 用户数据处理 

### 2.1. 用户注册

#### 2.1.1. 密码加密

加密算法有：对称加密、非对称加密。无论是哪种，在已知加密过程的各项数据参数后，都可以根据密文运算得到原文。

通常，密码的存储并不使用这些加密算法，而是使用消息摘要（Message Digest）算法。

消息摘要的特征有：

- 使用特定的摘要算法，得到的摘要数据的长度是固定的；

- 使用相同的原文，必然得到相同的摘要；

- 使用不同的原文，可能得到相同的摘要，但是，机率非常非常低；

- 消息摘要是不可被逆运算的！

常见的消息摘要算法有SHA家族（Secure Hash Algorithm）算法，MD系列。

在Java原生API中，有`java.security.MessageDigest`类，用于处理消息摘要运算，但是，使用相对繁琐，通常，会使用其它API来实现，例如：

	String password = "1234";
	String md5 = org.springframework.util.DigestUtils.md5DigestAsHex(
				password.getBytes()).toUpperCase();
	System.out.println(md5);
		
	md5 = org.apache.commons.codec.digest.DigestUtils.md5Hex(password).toUpperCase();
	System.out.println(md5);
		
	String sha256 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(password).toUpperCase();
	System.out.println(sha256);

在Spring和Apache中都有`DigestUtils`工具类，可以用于摘要运算，前者需要添加Spring的依赖，后者需要添加`commons-codec`的依赖：

	<dependency>
		<groupId>commons-codec</groupId>
		<artifactId>commons-codec</artifactId>
		<version>1.10</version>
	</dependency>

**关于MD5解密**

如果希望根据摘要数据，进行逆运算，得到原文，才算是破解，本身就是对摘要算法的误解！

在网上大量的在线破解，本质上都是“反查”，即，在这些网站的数据库中，记录了大量的原文与摘要的对应关系，对于简单的原文执行的摘要运算，可能都已经被收录了，所以，可以查询到原文，但是，使用相对比较复杂的原文运算得到的摘要数据，往往都是无法反查的，因为这些网站可能没有收集这些数据！

所以，MD5依然是不可逆运算的，用于密码加密，是安全的！

**进一步提升密码的安全程度**

简单的密码存在反查风险，通常，可改进的方案有：

1. 增加原文的复杂程度，例如`P@ss8888W0rD`；

2. 多重加密；

3. 在加密过程中添加盐；

4. 综合以上应用方式。

#### 2.1.2. 用户注册－持久层

应该先创建项目：`cn.tedu.store` / `TeduStore`。

创建数据库：`tedu_store`

创建数据表：

	CREATE TABLE t_user (
		id INT AUTO_INCREMENT,
		username VARCHAR(20) UNIQUE NOT NULL,
		password CHAR(32) NOT NULL,
		avatar VARCHAR(100),
		gender INT,
		phone VARCHAR(20),
		email VARCHAR(50),
		salt CHAR(36),
		is_delete INT,
		created_time DATETIME,
		created_user VARCHAR(20),
		modified_time DATETIME,
		modified_user VARCHAR(20),
		PRIMARY KEY(id)
	) DEFAULT CHARSET=UTF8;

先创建实体类的基类`cn.tedu.store.entity.BaseEntity`，它是一个抽象类，在其中声明关于日志的4个属性。

然后创建实体类`cn.tedu.store.entity.User`，继承自以上`BaseEntity`类，属性设计与以上数据表的字段设计保持一致！

检查持久层的相关配置是否正确，重点在于：`db.properties`中`url`属性中的数据库名称、`password`属性的值、`spring-dao.xml`中关于MyBatis的配置项中，接口文件的包名和映射文件的文件夹名称。

创建持久层接口`cn.tedu.store.mapper.UserMapper`，并声明抽象方法：

	Integer insert(User user);

	User findUserByUsername(String username);

然后，在`src\main\resources\mappers\UserMapper.xml`中配置以上2个方法的映射。

#### 2.1.2. 用户注册－业务层

通常，会创建业务异常的基类`cn.tedu.store.service.ex.ServiceException`。

根据分析，注册时可能抛出2种异常，则先创建这2个异常类：`cn.tedu.store.service.ex.UsernameConflictException`和`cn.tedu.store.service.ex.InsertDataException`，这2个异常都应该继承自`ServiceException`。

创建`cn.tedu.store.service.IUserService`业务层接口，然后声明抽象方法，原则是需要什么功能，就声明什么方法：

	User reg(User user) 
		throws UsernameConflictException, 
			InsertDataException;

然后，创建业务层的实现类`cn.tedu.store.service.impl.UserServiceImpl`，添加`@Service`注解，并检查`spring-service.xml`中组件扫描的包是否匹配，声明持久层对象`@Autowired private UserMapper userMapper;`

实现以上方法：

	public User reg(User user) throws UsernameConflictException {
		// 根据尝试注册的用户名查询用户数据
		// 判断是否查询到数据
			// 是：查询到数据，即用户名被占用，则抛出UsernameConflictException异常
			// 否：没有查询到数据，即用户名没有被占用，则执行插入用户数据，获取返回值
			// 执行返回
	}# 商城项目

## 1. 数据分析

通过观察静态页面，当前项目中至少包括以下类型的数据：商品，商品分类，用户 ，收货地址，购物车，收藏，订单。

关于以上数据，处理的顺序可以是：用户，收货地址，商品分类，商品，购物车，收藏，订单。

每项数据的处理都应该是：增，查，删，改。

每个功能的处理都应该是：持久层，业务层，控制器层，前端界面。

## 2. 用户数据处理 

### 2.1. 用户注册

#### 2.1.1. 密码加密

加密算法有：对称加密、非对称加密。无论是哪种，在已知加密过程的各项数据参数后，都可以根据密文运算得到原文。

通常，密码的存储并不使用这些加密算法，而是使用消息摘要（Message Digest）算法。

消息摘要的特征有：

- 使用特定的摘要算法，得到的摘要数据的长度是固定的；

- 使用相同的原文，必然得到相同的摘要；

- 使用不同的原文，可能得到相同的摘要，但是，机率非常非常低；

- 消息摘要是不可被逆运算的！

常见的消息摘要算法有SHA家族（Secure Hash Algorithm）算法，MD系列。

在Java原生API中，有`java.security.MessageDigest`类，用于处理消息摘要运算，但是，使用相对繁琐，通常，会使用其它API来实现，例如：

	String password = "1234";
	String md5 = org.springframework.util.DigestUtils.md5DigestAsHex(
				password.getBytes()).toUpperCase();
	System.out.println(md5);
		
	md5 = org.apache.commons.codec.digest.DigestUtils.md5Hex(password).toUpperCase();
	System.out.println(md5);
		
	String sha256 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(password).toUpperCase();
	System.out.println(sha256);

在Spring和Apache中都有`DigestUtils`工具类，可以用于摘要运算，前者需要添加Spring的依赖，后者需要添加`commons-codec`的依赖：

	<dependency>
		<groupId>commons-codec</groupId>
		<artifactId>commons-codec</artifactId>
		<version>1.10</version>
	</dependency>

**关于MD5解密**

如果希望根据摘要数据，进行逆运算，得到原文，才算是破解，本身就是对摘要算法的误解！

在网上大量的在线破解，本质上都是“反查”，即，在这些网站的数据库中，记录了大量的原文与摘要的对应关系，对于简单的原文执行的摘要运算，可能都已经被收录了，所以，可以查询到原文，但是，使用相对比较复杂的原文运算得到的摘要数据，往往都是无法反查的，因为这些网站可能没有收集这些数据！

所以，MD5依然是不可逆运算的，用于密码加密，是安全的！

**进一步提升密码的安全程度**

简单的密码存在反查风险，通常，可改进的方案有：

1. 增加原文的复杂程度，例如`P@ss8888W0rD`；

2. 多重加密；

3. 在加密过程中添加盐；

4. 综合以上应用方式。

#### 2.1.2. 用户注册－持久层

应该先创建项目：`cn.jacob.store` / `SampleStore`。

创建数据库：`jacob_store`

创建数据表：

	CREATE TABLE t_user (
		id INT AUTO_INCREMENT,
		username VARCHAR(20) UNIQUE NOT NULL,
		password CHAR(32) NOT NULL,
		avatar VARCHAR(100),
		gender INT,
		phone VARCHAR(20),
		email VARCHAR(50),
		salt CHAR(36),
		is_delete INT,
		created_time DATETIME,
		created_user VARCHAR(20),
		modified_time DATETIME,
		modified_user VARCHAR(20),
		PRIMARY KEY(id)
	) DEFAULT CHARSET=UTF8;

先创建实体类的基类`cn.jacob.store.entity.BaseEntity`，它是一个抽象类，在其中声明关于日志的4个属性。

然后创建实体类`cn.jacob.store.entity.User`，继承自以上`BaseEntity`类，属性设计与以上数据表的字段设计保持一致！

检查持久层的相关配置是否正确，重点在于：`db.properties`中`url`属性中的数据库名称、`password`属性的值、`spring-dao.xml`中关于MyBatis的配置项中，接口文件的包名和映射文件的文件夹名称。

创建持久层接口`cn.jacob.store.mapper.UserMapper`，并声明抽象方法：

	Integer insert(User user);

	User findUserByUsername(String username);

然后，在`src\main\resources\mappers\UserMapper.xml`中配置以上2个方法的映射。

#### 2.1.2. 用户注册－业务层

通常，会创建业务异常的基类`cn.jacob.store.service.ex.ServiceException`。

根据分析，注册时可能抛出2种异常，则先创建这2个异常类：`cn.jacob.store.service.ex.UsernameConflictException`和`cn.jacob.store.service.ex.InsertDataException`，这2个异常都应该继承自`ServiceException`。

创建`cn.jacob.store.service.IUserService`业务层接口，然后声明抽象方法，原则是需要什么功能，就声明什么方法：

	User reg(User user) 
		throws UsernameConflictException, 
			InsertDataException;

然后，创建业务层的实现类`cn.jacob.store.service.impl.UserServiceImpl`，添加`@Service`注解，并检查`spring-service.xml`中组件扫描的包是否匹配，声明持久层对象`@Autowired private UserMapper userMapper;`

实现以上方法：

	public User reg(User user) throws UsernameConflictException {
		// 根据尝试注册的用户名查询用户数据
		// 判断是否查询到数据
			// 是：查询到数据，即用户名被占用，则抛出UsernameConflictException异常
			// 否：没有查询到数据，即用户名没有被占用，则执行插入用户数据，获取返回值
			// 执行返回
	}

还需要添加以下辅助方法：

	private User insert(User user) {
		// 在参数user中封装那些不由外部提供的数据：
		// 1. 生成随机盐，并封装到user中
		// 2. 取出user中原密码执行加密，并封装回user中
		// 3. 设置isDelete为0
		// 4. 日志的4项

		// 调用持久层对象的方法实现功能，并获取返回值
		// 判断返回值是否为1
			// 是：返回参数对象 
			// 否：抛出InsertDataException异常
	}

	private User findUserByUsername(String username) {
		// TODO 检查用户名基本格式是否正确
		// 调用持久层对象的方法实现功能
	}

	private String getEncrpytedPassword(String password, String salt) {
		// 将原密码加密
		// 将盐加密
		// 将以上2个加密结果拼接
		// 循环5次加密
		// 返回
	}

完成后，执行单元测试。
## 2. 用户数据处理 

### 2.1. 用户注册

#### 2.1.3. 用户注册－控制器层

创建`cn.jacob.store.entity.ResponseResult`类：

	public class ResponseResult<T> {
		private Integer state = 200;	// 操作状态
		private String message;		// 提示信息
		private T data;				// 数据

		public ResponseResult(Integer state, Exception e) {
			super();
			this.state = state;
			this.message = e.getMessage();
		}
	}

创建控制器类的基类`cn.jacob.store.controller.BaseController`，声明为`abstract`抽象类，并且不需要添加注解！在这个类，添加方法实现对异常的处理：

	@ExceptionHandler(ServiceException.class)
	@ResponseBody
	public ResponseResult<Void> handleException(Exception e) {
		// 判断异常类型，并进行处理
		if (e instanceof UsernameConflictException) {
			// 用户名被占用
			return new ResponseResult<Void>(401, e);
		} else if (e instanceof InsertDataException) {
			// 插入数据错误
			return new ResponseResult<Void>(501, e);
		}
	}

创建控制器类`cn.jacob.store.controller.UserController`，添加`@Controller`注解和`@RequestMapping("/user")`注解，继承自以上`BaseController`。

检查`spring-mvc.xml`中组件扫描的包是否正确！

在类中声明`@Autowired private IUserService userService;`

分析所处理的请求：

	请求路径：/user/handle_reg.do
	请求类型：POST
	请求参数：User
	响应方式：ResponseResult

则，在控制器类中添加处理请求的方法：

	@RequestMapping(value="/handle_reg.do", method=RequestMethod.GET)
	@ResponseBody
	// 当前方法的返回值中的泛型表示需要给客户端的结果中，除了操作状态和提示信息以外，还给什么数据
	public ResponseResult<Void> handleReg(User user) {
		// 调用业务层对象实现注册
		userService.reg(user);
		// 执行返回
		return new ResponseResult<Void>();
	}

完成后，通过`http://localhost:8080/jacobStore/user/handle_reg.do?username=chrome&password=1234`在浏览器中测试，如果无误，则完成，并将请求类型限制为`POST`。

**关于响应方式**

目前，响应方式可以是：转发、重定向、正文。

其中，转发和重定向都会导致用户端的界面跳转，而正文可以是JSON格式，如果通过AJAX提交请求并处理结果，则用户端的界面可以不发生跳转。

主流的做法是服务器只响应正文，且是JSON格式，好处在于前端界面可以结合AJAX技术，实现局部刷新，进而有流量消耗小、响应速度快的优势，并且，由于服务器只提供数据服务，完全不考虑界面的处理，则对客户端也就没有要求，客户端可以自行使用任何技术进行处理，所以，也就能够适用于多种不同的客户端，例如：浏览器、Android APP、iOS APP等。

使用这样的做法，也可以使得开发人员的分工更加明确，即服务器端的开发人员不需要考虑任何客户端技术。

### 2.2. 用户登录

#### 2.2.1. 用户登录-持久层

关于登录，持久层的任务只有**根据用户名查询用户数据**，此前已经完成该功能，则检查：**查询结果中是否包含登录时必要的字段：id, username, password, salt。**

如果检查无误，则持久层无须进一步开发。

#### 2.2.2. 用户登录-业务层

在`cn.jacob.store.service.ex`中创建2个新的异常类：`UserNotFoundException`和`PasswordNotMatchException`，均继承自`ServiceException`。

基于**需要执行什么功能，就在业务层接口中声明什么方法**的原则，首先，在业务层接口中声明：

	User login(String username, String password) throws UserNotFoundException, PasswordNotMacthException;

然后，在业务层实现类中实现以上方法：

	public User login(String username, String password) throws UserNotFoundException, PasswordNotMacthException{
		// 根据用户名查询用户数据
		// 判断是否查询到数据
			// 是：查询到与用户名匹配的数据，获取盐值
				// 基于参数密码与盐值进行加密
				// 判断加密结果与用户数据中的密码是否匹配
					// 是：返回用户数据
					// 否：密码不正确，抛出PasswordNotMacthException异常
			// 否：没有与用户名匹配的数据，则抛出UserNotFoundException异常
	}

完成后，执行单元测试。

#### 2.2.3. 用户登录-控制器层

分析需要处理的请求：

	请求路径：/user/handle_login.do
	请求类型：POST
	请求参数：username(*), password(*), HttpSession
	响应方式：ResponseResult

调用业务层方法实现功能时，新抛出的异常：

	UserNotFoundException
	PasswordNotMatchException

基于以上分析，应该先在`BaseController`中处理异常的方法中，添加对以上2种异常的处理！

然后，在`UserController`中添加处理请求的方法：

	@RequestMapping(value="/handle_login.do", method=RequestMethod.GET)
	@ResponseBody
	public ResponseResult<Void> handleLogin(
		@RequestParam("username") String username,
		@RequestParam("password") String password,
		HttpSession session) {
		// 调用业务层对象的login()方法，并获取返回值
		// 将用户id和用户名封装到session中
		// 返回
	}

完成后，通过`http://localhost:8080/jacobStore/user/handle_login.do?username=root&password=1234`在浏览器中测试，测试通过后，将请求类型限制为`POST`。

## 2. 用户数据处理 

### 2.2. 用户登录

#### 2.2.3. 用户登录-控制器层

关于用户提交的数据，需要验证基本数据格式，然后，再执行后续操作，即：如果数据基本格式都不正确，例如没有输入正确格式的用户名，根本就不需要查询数据库，就可以视为登录失败！

**通常，可以视为：用户提交的所有数据都是不可靠的！**

在服务器端，接收到数据的第一时刻，就应该检验数据的有效性，即验证数据的基本格式和内容的组成，甚至内容中是否包括非法内容（敏感词等等），而第一时刻，可以是过滤器或拦截器，也可以是控制器，通常是在控制器中进行处理。

处理方式可以使用正则表达式进行判断。

通常，建议在业务层执行相同的判断！其实，绝大部分的数据处理流程是`Controller > Service`，所以，如果控制器已经判断过，则业务层是不需要判断的！但是，也存在某些业务功能的设计，是不需要经过控制器，就可以直接调用业务层的！在这种情况下，可以视为没有验证数据就开始执行业务，则是不安全的做法，所以，业务层也应该验证数据的有效性！

其实，完整的验证应该是：前端页面通过JavaScript验证，如果数据合法，则允许提交到服务器端，在服务器端，首先由控制器验证，如果数据合法，则允许调用业务层对象执行数据访问，然后，由业务层再次验证数据的有效性，如果数据合法，则允许向后继续执行。所以，总的来说，在前端页面、控制器、业务层都需要验证数据！其实，只有业务层的验证，才是真正的保障数据安全的验证，而前序的验证，是为了减轻后续操作的负担，避免将不符合规则的数据向后提交而产生的验证。

#### 2.2.4. 前端页面

参考注册页面的开发流程和代码。

### 2.3. 修改密码

#### 2.3.1. 持久层

首先，持久层中必须存在**修改密码**的功能，对应的SQL语句大致是：

	UPDATE t_user SET password=? WHERE id=?

以上设计中，只体现了修改密码的功能，而并不考虑修改密码的业务，毕竟，不是所有人或所有应用场景中，都需要验证原密码才可以执行修改！

基于本次修改功能是需要验证原密码的，该验证操作将在业务层来组织，则业务层将需要**获取该用户的原密码**功能，由于用户登录后，会在session中存入id，所以，在持久层应该实现**根据id查询该用户的原始密码**功能：

	SELECT password, salt FROM t_user WHERE id=?

所以，实现**修改密码**时，持久层需要完成以上2个任务，则在`UserMapper.java`接口中添加新的抽象方法：

	User findUserById(Integer id);

	Integer updatePassword(
		@Param("id") Integer id, 
		@Param("password") String password);

然后，在`UserMapper.xml`中配置以上方法的映射：

	<!-- 根据用户id查询用户数据 -->
	<!-- User findUserById(Integer id) -->
	<select id="findUserById"
		resultType="cn.jacob.store.entity.User">
		SELECT 
			password, salt
		FROM 
			t_user
		WHERE 
			id=#{id}
	</select>
	
	<!-- 更新密码 -->
	<!-- Integer updatePassword(
			@Param("id") Integer id, 
			@Param("password") String password); -->
	<update id="updatePassword">
		UPDATE t_user
		SET password=#{password}
		WHERE id=#{id}
	</update>

完成后，执行单元测试。

#### 2.3.2. 业务层

首先，在业务层接口中添加抽象方法：

**设计业务方法原则1：需要执行什么任务，就设计什么方法！**

**设计业务方法原则2：只考虑操作成功的情况下，需要返回什么数据，不通过返回值来表达操作成功与否！**

**设计业务方法原则3：每个持久层的方法，在业务层中，都有一个直接调用它的方法！**

	void changePassword(
		Integer id, String oldPassword, String newPassword); 

然后，在实现类实现以上方法：

	public void changePassword(
		Integer id, String oldPassword, String newPassword) {
		// 根据id查询用户数据
		// 判断用户数据是否存在（可能用户登录后数据被删除）
		// 是：用户数据存在，获取盐值
		// 将oldPassword加密
		// 将加密后的密码，与刚才查询结果中的密码对比
			// 是：基于盐和newPassword加密
			// 更新密码
			// 否：原密码错误，抛出PasswordNotMatchException
		// 否：用户数据不存在，抛出UserNotFoundException
	}

**组织业务的代码，不直接调用持久层中的方法**

	private User findUserById(Integer id) {
		return userMapper.findUserById(id);
	}

	private Integer updatePassword(Integer id, String password) {
		直接调用持久层功能来实现，获取返回值
		判断返回值
	}

完成后，执行单元测试。

#### 2.3.3. 控制器层

先确定是否抛出了新的异常，如果有，则在`BaseController`中进行处理，本次需要处理的有`UpdateDataException`。

然后，设计**处理修改密码**的请求：

	请求路径：/user/change_password.do
	请求类型：POST
	请求参数：old_password(*), new_password(*), HttpSession
	响应方式：ResponseResult

然后，在`UserController`中添加处理请求的方法：

	@RequestMapping(value="/change_password.do", method=RequestMethod.GET)
	@ResponseBody
	public ResponseResult<Void> handleChangePassword(
		@ReuqestParam("old_password") String oldPassword,
		@ReuqestParam("new_password") String newPassword,
		HttpSession session) {
		// 验证密码格式

		// 从Session中获取当前用户的id
		// 通过业务执行修改密码
		userService.changePassword(id, oldPassword, newPassword);
		// 返回
	} 

完成后，先登录，通过`http://localhost:8080/jacobStore/user/change_password.do?old_password=1234&new_password=8888`，测试完成后，将请求类型限制为`POST`类型。

**关于登录，请使用拦截器！**

### 2.3. 修改密码

#### 2.3.4. HTML访问过滤器

修改密码的页面`password.html`应该需要登录，才允许访问，由于拦截器`Interceptor`是SpringMVC中的组件，而当前项目中`DispatcherServlet`只处理了`*.do`的请求，所以，所有`*.html`的请求将不经过SpringMVC的执行流程，拦截器也就无法对HTML页面的访问进行拦截操作。

针对这个问题，需要使用Java EE中的过滤器`Filter`来实现，创建`HtmlAccessFilter`，并且，在`web.xml`中添加配置，对`*.html`进行过滤：

	<!-- 配置HTML访问过滤器 -->
	<filter>
		<filter-name>HtmlAccessFilter</filter-name>
		<filter-class>cn.jacob.store.filter.HtmlAccessFilter</filter-class>
	</filter>

	<filter-mapping>
		<filter-name>HtmlAccessFilter</filter-name>
		<url-pattern>*.html</url-pattern>
	</filter-mapping>

然后，编写过滤器中的代码，规则包括：1) 白名单中的页面直接放行；2) 已登录的直接放行；3) 其它的html页面的访问全部拦截。

其中，白名单应该在`init()`方法中创建，只执行一次。

放行的表现是调用过滤器链的`doChain()`方法。

具体代码如下：

	/**
	 * HTML访问过滤器
	 */
	public class HtmlAccessFilter implements Filter {
		/**
		 * 白名单，允许直接访问的页面列表
		 */
		private List<String> whiteList = new ArrayList<String>();
		
		public void init(FilterConfig arg0) throws ServletException {
			// 确定白名单
			whiteList.add("register.html");
			whiteList.add("login.html");
			whiteList.add("footerTemplate.html");
			whiteList.add("leftTemplate.html");
			whiteList.add("topTemplate.html");
			// 输出
			System.out.println("无需登录的页面列表：");
			for (String page : whiteList) {
				System.out.println(page);
			}
		}
	
		public void doFilter(ServletRequest arg0, 
				ServletResponse arg1, 
				FilterChain filterChain)
				throws IOException, ServletException {
			// 获取当前页面
			HttpServletRequest request 
				= (HttpServletRequest) arg0;
			String uri = request.getRequestURI();
			int beginIndex = uri.lastIndexOf("/") + 1;
			String fileName = uri.substring(beginIndex);
			System.out.println("当前请求页面：" + fileName);
			
			// 判断当前访问的是哪个页面
			// 如果是无需登录的页面，直接放行，例如：login.html
			if (whiteList.contains(fileName)) {
				System.out.println("\t无需登录，直接放行");
				// 继续执行过滤器链
				filterChain.doFilter(arg0, arg1);
				return;
			}
			
			// 如果是需要登录的页面，判断session，决定放行或重定向
			HttpSession session
				= request.getSession();
			if (session.getAttribute("uid") != null) {
				// Session中有uid，表示已登录，直接放行
				System.out.println("\t已经登录，直接放行");
				// 继续执行过滤器链
				filterChain.doFilter(arg0, arg1);
				return;
			}
			
			// 执行到此处，表示当前页面不在白名单中，且未登录，则拦截
			// 拦截的表现是：重定向到登录页
			System.out.println("\t拦截当前页面，将重定向到登录页！");
			HttpServletResponse response
				= (HttpServletResponse) arg1;
			response.sendRedirect("login.html");
		}
	
		public void destroy() {
		}
	}

### 2.4. 修改个人资料

#### 2.4.1. 持久层

该功能对应的SQL语句大致是：

	UPDATE 
		t_user 
	SET 
		gender=?, phone=?, email=?
	WHERE id=?

所以，在持久层接口中添加抽象方法：

	Integer updateInfo(User user);

然后，配置以上抽象方法的映射。

完成后，执行单元测试。

#### 2.4.2. 业务层

在业务接口中声明抽象方法：

	void changeInfo(User user);

在业务层实现类中实现以上方法：

	public void changeInfo(User user) {
		// 判断用户id是否存在
		if (user.getId() == null) {
			throw new UpdateDataException("id...");
		}

		// 检查其它数据的格式

		// 判断用户数据是否存在于数据表中
		User data = findUserById(user.getId());
		if (data == null) {
			throw new UserNotFoundException("...");
		}

		// 补全需要更新的数据
		user.setModifiedUser(data.getUsername());
		user.setModifiedTime(new Date());

		// 执行更新
		updateInfo(user);
	}

	private void updateInfo(User user) {
		Integer rows = userMapper.updateInfo(user);
		if (rows != 1) {
			throw new UpdateDataException("....");
		}
	}

**注意：请检查UserMapper.xml中关于findUserById()的映射中，必须查询username字段，如果没有，请补全。**

完成后，执行单元测试。

#### 2.4.3. 控制器层

先检查是否抛出了新的异常，此次抛出的是`UserNotFoundException`和`UpdateDataException`，这2个都是处理过的异常，则无需再次处理！如果自行抛出了**手机号码格式异常**、**电子邮件格式异常**，则应该在`BaseController`中对这2个新的异常进行处理！

然后，设计处理**修改个人信息**的请求：

	请求路径：/user/change_info.do
	请求类型：POST
	请求参数：User(phone, email, gender), HttpSession(用户id)
	响应方式：ResponseResult<Void>
	是否拦截：是，但无需修改配置

然后，在`UserController`中添加处理请求的方法：

	@RequestMapping(value="/change_info.do", method=RequestMethod.GET)
	@ResponseBody
	public ResponseResult<Void> handleChangeInfo(
		User user, HttpSession session) {
		// 获取id
		// 执行
		// 返回
	}

完成后，通过`http://localhost:8080/jacobStore/user/change_info.do?phone=x&email=x&gender=1`在浏览器中测试（由于有了登录拦截器，未登录时，会被重定向），测试完成后，将请求类型限制为`POST`。

### 2.4. 修改个人资料

#### 2.4.4. 前端页面

不同于**注册**、**登录**、**修改密码**，此次显示的**修改个人资料**页面，应该是**刚打开页面时，就直接显示当前登录的用户的资料**！这个效果，可以通过**刚打开页面时，就向服务器请求当前用户的资料，在处理响应结果时，直接将内容显示到各控件中**来实现。

要实现这个需求，需要服务器端能够**根据当前登录的用户的id获取用户的用户名、性别、手机号码、邮箱**。首先，持久层已经有`findUserById(Integer id)`方法可以适用于当前需求，应该检查持久层的映射中，查询的字段是否完整；然后，此前的业务层实现类中已经存在该方法，但是，由于接口中没有声明该方法，且最终控制器中声明的是接口的对象，为了保证方法的调用，应该先在接口中声明`User findUserById(Integer id);`方法，再将实现类原有的方法的访问权限修改为`public`；再接下来，应该保证控制器能够响应所需的数据，则：

	请求路径：/user/info.do
	请求类型：GET
	请求参数：HttpSession
	响应方式：ResponseResult<User>
	是否拦截：是，但无需修改配置

所以，在`UserController`中添加处理请求的方法：

	@RequestMapping("/info.do")
	@ResponseBody
	public ResponseResult<User> getInfo(HttpSession session) {
		// 获取uid
		// 查询
		// 创建返回值对象
		// 把查询结果封装到返回值对象的data属性中
		// 返回
	}

### 2.5. 文件上传

#### 2.5.1. 创建WEB页面

文件上传的HTML页面中需要表单，且`method="post`和`enctype="multipart/form-data"`，使用的控件是`<input type="file" />`：

	<form method="post"  action="upload.do"
		enctype="multipart/form-data">
		<div><input name="file" type="file" /></div>
		<div><input type="submit" value="上传" /></div>
	</form>

#### 3.2. 添加依赖

SpringMVC中的文件上传依赖apache的`commons-fileupload`，所以，添加依赖：

	<!-- 文件上传 -->
	<dependency>
		<groupId>commons-fileupload</groupId>
		<artifactId>commons-fileupload</artifactId>
		<version>1.3.3</version>
	</dependency>

#### 3.3. 配置CommonsMultipartResolver

使用SpringMVC的上传，必须在Spring的配置文件中配置`CommonsMultipartResolver`，且`id`必须是`multipartResolver`，该节点可以有更多配置，也可以不添加配置，最简化配置如下：

	<!-- CommonsMultipartResolver -->
	<bean id="multipartResolver"
		class="org.springframework.web.multipart.commons.CommonsMultipartResolver" />

#### 3.4. 创建控制器处理请求

在服务器端处理上传请求时，需要将用户提交的上传文件声明为`CommonsMultipartFile`类型，它表示用户上传的文件，调用该参数对象的`transferTo(File)`方法即可将文件保存在服务器端的某个位置，通常，推荐将文件保存在`webapp`目录下，以便于用户可以通过HTTP协议进行访问，并且，通常还会专门创建某个文件夹，用于存储用户上传的文件，通过`HttpServletRequest`对象的`getServletContext.getRealPath(String)`方法可以获取到`webapp`下某文件夹的实际路径：

	@Controller
	public class UploadController {
	
		@RequestMapping("/upload.do")
		public String handleUpload(
				HttpServletRequest request,
				@RequestParam("file") CommonsMultipartFile file) 
					throws IllegalStateException, IOException {
			// CommonsMutltpartFile是SpringMVC封装的上传数据
			String parentPath = request
				.getServletContext().getRealPath("upload");
			// 确定文件夹，是webapp下的upload
			File parentFile = new File(parentPath);
			// 确定文件名
			String fileName = "1.jpg";
			// 确定上传的文件存储到的目标文件
			File dest = new File(parentFile, fileName);
			// 将上传的数据进行存储
			file.transferTo(dest);
			return null;
		}
		
	}

通常，上传的文件都必须限制文件类型，可以通过`CommonsMultipartFile`对象的`String getContentType()`方法获取文件的MIME类型，例如`image/jpeg`，更多类型可以在Tomcat的`conf/web.xml`中查找。

且上传的文件必须限制文件大小，因为过大的文件可能导致上传体验较差，并且，产生的流量消耗较大，占用较多的服务器端存储空间，通过`CommonsMultipartFile`对象的`long getSize()`方法可以获取文件的大小，例如`12345`，是以字节为单位的。

还可以通过`CommonsMultipartFile`对象的`String getOriginalFileName()`方法获取原始文件名，即用户端的文件名，主要通过该文件名截取出文件的扩展名，用于最终保存文件。

最终保存的文件名应该自定义命名规则，以保证每个用户上传的文件彼此不会覆盖，通常会使用时间、随机数等作为文件名的某个部分。

除此以外，还可以通过`getBytes()`和`getInputStream()`获取用户上传的原始数据/流，然后自行创建输出流，将数据写入到服务器端的文件中，而自定义输出流的写入，可以根据实际情况提高写入效率！

关于在Spring的配置文件中配置的`CommonsMultipartResolver`，可以配置以下属性：

- maxUploadSize：最大上传大小，即每次上传的文件不允许超过多少字节！假设同时上传5个文件，则5个文件的大小总和不允许超过设置值。

- maxUploadSizePerFile：每个上传的文件不允许超过多少字节，因为单次上传其实可以选中多个文件！假设同时上传5个文件，则每个文件的大小都不允许超过设置值，而5个文件的总大小允许超过设置值。.

- maxInMemorySize：上传的文件在内存中最大占多少空间。

- defaultEncoding：默认编码。

**注意：在HTML页面中，在<input type="file" />标签中添加multiple="multiple"，则上传时可以同时选中多个文件提交上传，且，在服务器端处理时，处理请求的方法中应该声明CommonsMultipartFile[] files参数来接收多个文件的数据。**

### 2.6. 头像上传

#### 2.6.1. 分析

上传头像时，应该把头像文件的路径存储到数据表中，例如`upload/201812021610041.jpg`，后续，当需要显示头像时，使用`<img src="upload/201812021610041.jpg" />`即可显示。

所以，上传头像的操作主要是：1) 将文件存储到指定的目录中；2) 将文件的路径存储到数据表中。

#### 2.6.2. 持久层

基于以上分析，在上传头像功能中，持久层的任务是将文件的路径存储到数据表中，即**更新当前用户的avatar字段值**。

所以，在持久层接口中声明抽象方法：

	Integer updateAvatart(
		@Param("id") Integer id,
		@Param("avatar") String avatar);

执行的SQL语句格式为：

	UPDATE t_user SET avatar=? WHERE id=?

基于以上内容配置映射，完成后，测试。

#### 2.6.3. 业务层

在业务层接口中声明抽象方法：

	void changeAvatar(Integer id, String avatar) 
		throws UserNotFoundException, 
			UpdateDataException;

在业务层实现类中实现以上方法：

	public void changeAvatar(Integer id, String avatar) 
		throws UserNotFoundException, 
			UpdateDataException{
		if (findUserById(id) == null) {
			throw new UserNotFoundException("...");
		}
		updateAvatar(id, avatar);
	}

	private void updateAvatar(Integer id, String avatar) {
		Integer rows = userMapper.updateAvatar(id, avatar);
		if (rows != 1) {
			throw new UpdateDataException("...");
		}
	}

#### 2.6.4. 控制器层

先按照上传文件的开发流程，完成：添加依赖、配置`CommonsMultipartResolver`，然后，设计请求：

	请求路径：/user/upload.do
	请求类型：POST
	请求参数：HttpServletRequest, HttpSession, CommonsMultipartFile
	响应方式：ResponseResult<String>
	是否拦截：是，登录拦截，但无需修改配置 

在`UserController`中添加处理请求的方法：

	public static final long MAX_UPLOAD_SIZE = 1 * 1024 * 1024;

	public static final List<String> 
		CONTENT_TYPE_WHITE_LIST 
			= new ArrayList<String>();

	@PostConstruct
	public void init() {
		CONTENT_TYPE_WHITE_LIST.add("image/jpeg");
		CONTENT_TYPE_WHITE_LIST.add("image/png");
	}

	@RequestMapping(value="/upload.do", 
		method=RequestMethod.POST)
	@ResponseBody
	public ResponseResult<String> handleUpload(
		HttpServletRequest request,
		HttpSession session,
		CommonsMultipartFile file) {
		// 检查上传的文件大小
		long fileSize = file.getSize();
		if (fileSize > MAX_UPLOAD_SIZE) {
			return new ResponseResult<String>(?, "");
		}

		// 检查上传的文件类型
		String contentType = file.getContentType();
		if (!CONTENT_TYPE_WHITE_LIST.contains(contentType)) {
			return new ResponseResult<String>(?, "");
		}

		// 确定保存上传文件的文件夹名称
		String uploadDirName = "upload";

		// 获取id
		Integer id = xxxx;

		// 确定文件夹对象
		String uploadDirPath = request.getServletContext().getRealPath(uploadDirName);
		File uploadDir = new File(uploadDirPath);
		if (!uploadDir.exists()) {
			uploadDir.mkdirs();
		}

		// 确定文件名
		int beginIndex = file.getOriginalFileName().lastIndexOf(".");
		String suffix = file.getOriginalFileName().substring(beginIndex);
		String fileName = getFileName(id) + suffix;

		// 创建dest对象，是File类型	
		File dest = new File(uploadDir, fileName);
		// 执行保存
		file.transferTo(dest);
		// 更新数据表
		String avatar = uploadDirName + "/" + fileName;
		userService.changeAvatar(id, avatar);
		return null;
	}

	private String getFileName(Integer id) {
		// 基于id和时间返回文件名称
	}

	/**
	 * 用户上传的头像的最大尺寸，单位：字节
	 */
	private static final long AVATAR_MAX_SIZE = 1 * 1024 * 1024;
	/**
	 * 头像类型白名单
	 */
	private static final List<String> AVATAR_TYPE_WHITE_LIST = new ArrayList<String>();
	
	@PostConstruct
	public void init() {
		AVATAR_TYPE_WHITE_LIST.add("image/jpeg");
		AVATAR_TYPE_WHITE_LIST.add("image/png");
	}
	
	@RequestMapping(value="/upload.do",
		method=RequestMethod.POST)
	@ResponseBody
	public ResponseResult<String> handleUpload(
			HttpServletRequest request,
			HttpSession session,
			CommonsMultipartFile file) {
		// 检查是否上传了文件
		if (file.isEmpty()) {
			return new ResponseResult<String>(601, "读取文件中断，文件路径可能已经发生变化！");
		}
		// 检查文件大小
		long fileSize = file.getSize();
		if (fileSize > AVATAR_MAX_SIZE) {
			return new ResponseResult<String>(601, "读取文件中断，文件路径可能已经发生变化！");
		}
		// 检查文件类型
		String contentType = file.getContentType();
		if (!AVATAR_TYPE_WHITE_LIST
				.contains(contentType)) {
			return new ResponseResult<String>(601, "读取文件中断，文件路径可能已经发生变化！");
		}
		
		// 获取当前登录的用户的id
		Integer id = getUidFromSession(session);
		
		// 用户上传的文件存储到的文件夹的名称
		String uploadDirName = "upload";
		// 用户上传的文件存储到的文件夹的路径
		String parentDirPath
			= request.getServletContext()
				.getRealPath(uploadDirName);
		// 用户上传的文件存储到的文件夹
		File parentDir = new File(parentDirPath);
		// 确保文件夹存在
		if (!parentDir.exists()) {
			parentDir.mkdirs();
		}
		
		// 获取原始文件名
		String originalFileName = file.getOriginalFilename();
		// 获取原始文件的扩展名
		int beginIndex = originalFileName.lastIndexOf(".");
		String suffix = originalFileName.substring(beginIndex);
		// 用户上传的文件存储的文件名
		String fileName = getFileName(id) + suffix;
		// 确定用户上传的文件在服务器端的路径
		String avatar = uploadDirName + "/" + fileName;
		
		// 用户上传的文件存储到服务器端的文件对象
		File dest = new File(parentDir, fileName);
		
		// 将用户上传的文件存储到指定文件夹
		try {
			file.transferTo(dest);
		} catch (IllegalStateException e) {
			return new ResponseResult<String>(601, "读取文件中断，文件路径可能已经发生变化！");
		} catch (IOException e) {
			return new ResponseResult<String>(602, "读取数据出错！文件可能已被移动、删除，或网络连接中断！");
		}
		// 将用户的头像数据更新到数据表
		userService.changeAvatar(id, avatar);
		
		// 返回
		ResponseResult<String> rr
			= new ResponseResult<String>();
		rr.setData(avatar);
		return rr;
	}
	
	/**
	 * 获取上传文件的文件名，文件名的命名规则是：uid-yyyyMMddHHmmss
	 * @param uid 用户id
	 * @return 匹配格式的字符串
	 */
	private String getFileName(Integer uid) {
		Date date = new Date();
		SimpleDateFormat sdf = new SimpleDateFormat(
				"yyyyMMddHHmmss");
		return uid + "-" + sdf.format(date);
	}
	
# ------------------------------------------------------

抛出的新的异常：

	300-请求参数异常-RequestArgumentException

	303-上传文件大小超出限制-UploadFileSizeLimitException

	304-上传文件类型异常-UploadFileContentTypeException

	305-上传状态异常-UploadStateException

	306-上传文件读写异常-UploadIOException

调整后的控制器：

	@RequestMapping(value="/upload.do",
		method=RequestMethod.POST)
	@ResponseBody
	public ResponseResult<String> handleUpload(
			HttpServletRequest request,
			HttpSession session,
			CommonsMultipartFile file) {
		// 检查是否上传了文件
		if (file.isEmpty()) {
			throw new RequestArgumentException(
				"没有选择上传的文件，或上传的文件的内容为空！");
		}
		// 检查文件大小
		long fileSize = file.getSize();
		if (fileSize > AVATAR_MAX_SIZE) {
			throw new UploadFileSizeLimitException(
				"上传的文件大小超出限制！限制值为" + (AVATAR_MAX_SIZE / 1024) + "KByte。");
		}
		// 检查文件类型
		String contentType = file.getContentType();
		if (!AVATAR_TYPE_WHITE_LIST
				.contains(contentType)) {
			throw new UploadFileContentTypeException(
				"上传文件类型错误！允许的文件类型：" + AVATAR_TYPE_WHITE_LIST);
		}
		
		// 获取当前登录的用户的id
		Integer id = getUidFromSession(session);
		
		// 用户上传的文件存储到的文件夹的名称
		String uploadDirName = "upload";
		// 用户上传的文件存储到的文件夹的路径
		String parentDirPath
			= request.getServletContext()
				.getRealPath(uploadDirName);
		// 用户上传的文件存储到的文件夹
		File parentDir = new File(parentDirPath);
		// 确保文件夹存在
		if (!parentDir.exists()) {
			parentDir.mkdirs();
		}
		
		// 获取原始文件名
		String originalFileName = file.getOriginalFilename();
		// 获取原始文件的扩展名
		int beginIndex = originalFileName.lastIndexOf(".");
		String suffix = originalFileName.substring(beginIndex);
		// 用户上传的文件存储的文件名
		String fileName = getFileName(id) + suffix;
		// 确定用户上传的文件在服务器端的路径
		String avatar = uploadDirName + "/" + fileName;
		
		// 用户上传的文件存储到服务器端的文件对象
		File dest = new File(parentDir, fileName);
		
		// 将用户上传的文件存储到指定文件夹
		try {
			file.transferTo(dest);
		} catch (IllegalStateException e) {
			throw new UploadStateException("读取文件中断，文件路径可能已经发生变化！");
		} catch (IOException e) {
			throw new UploadIOException("读取数据出错！文件可能已被移动、删除，或网络连接中断！");
		}
		// 将用户的头像数据更新到数据表
		userService.changeAvatar(id, avatar);
		
		// 返回
		ResponseResult<String> rr
			= new ResponseResult<String>();
		rr.setData(avatar);
		return rr;
	}

## 3. 收货地址管理

### 3.1. 增加收货地址

#### 3.1.1.  增加收货地址-持久层

**数据表**

	CREATE TABLE t_address (
		id INT AUTO_INCREMENT,
		uid INT NOT NULL,
		recv_name VARCHAR(16) NOT NULL,
		recv_province CHAR(6),
		recv_city CHAR(6),
		recv_area CHAR(6),
		recv_district VARCHAR(30),
		recv_address VARCHAR(50),
		recv_phone VARCHAR(20),
		recv_tel VARCHAR(20),
		recv_zip CHAR(6),
		recv_tag VARCHAR(10),
		is_default INT,
		created_time DATETIME,
		created_user VARCHAR(20),
		modified_time DATETIME,
		modified_user VARCHAR(20),
		PRIMARY KEY(id)
	) DEFAULT CHARSET=UTF8;

> 数据库设计范式

**实体类**

创建`cn.jacob.store.entity.Address`，继承自`BaseEntity`。

**接口**

通常，每种类型的数据都有1张对应的数据表，有1个对应的实体类，也有1个对应的持久层接口。

创建`cn.jacob.store.mapper.AddressMapper`接口，并声明抽象方法：

	Integer insert(Address address);

**映射**

复制`UserMapper.xml`得到`AddressMapper.xml`，删除原有配置，将根节点的`namespace`属性值改为`cn.jacob.store.mapper.AddressMapper`，然后，配置以上抽象方法的映射：

	<insert id="insert" parameterType="xx"
		useGeneratedKeys="true"
		keyProperty="id">
		INSERT INTO t_address (
			uid, recv_name ...
		) VALUES (
			#{uid}, #{recvName} ...
		)
	</insert>

完成后，创建新的测试类，执行测试。

#### 3.1.2.  增加收货地址-业务层

在业务层存在业务逻辑：如果当前增加的收货地址是当前用户的第1条收货地址，则是默认收货地址，否则，不是默认收货地址。

所以，需要**根据用户查询有多少条收货地址**功能，则应该先在持久层添加抽象方法：

	Integer getCountByUid(Integer uid);

对应的SQL语句是：

	SELECT COUNT(id) FROM t_address WHERE uid=?

则继续配置相关映射，并执行测试。

创建业务接口`cn.jacob.store.serivce.IAddressService`，并声明抽象方法：

	Address addnew(Address address);

创建业务实现类`cn.jacob.store.service.AddressServiceImpl`，使用`@Service("addressService")`注解，声明`@Autowired private AddressMapper addressMapper`，并实现以上接口，并重写抽象方法：

	public Address addnew(Address address) {
		// 完善数据：recv_district，示例：河北省，石家庄市，长安区

		// 完善数据：is_default
		// 第1次增加的是默认，否则不默认
		Integer count = getCountByUid(address.getUid());
		address.setIsDefault(count > 0 ? 0 : 1);

		// 执行插入数据
		Address result = insert(address);
		return result;
	}

	private Address insert(Address address) {
		Integer rows = addressMapper.insert(address);
		if (rows != 1) {
			throw new InsertDataException("...");
		} else {
			return address;
		}
	}

	private Integer getCountByUid(Integer uid) {
		return addressMapper.getCountByUid(uid);
	}


#### 3.1.3.  增加收货地址-控制器层

#### 3.1.4.  增加收货地址-前端页面

### 3.2. 收货地址列表

### 3.3. 删除收货地址

### 3.4. 修改收货地址

## 3. 收货地址管理

### 3.1. 增加收货地址

#### 3.1.2.  增加收货地址-业务层

此次业务操作中并没有抛出新的异常，所以，无需在`BaseController`中添加处理新的异常。

然后，设计处理请求：

	请求路径：/address/addnew.do
	请求类型：POST
	请求参数：Address, HttpSession
	响应方式：ResponseResult<Void>
	是否拦截：是，登录拦截，需要添加新的配置

由于需要登录拦截，则应该在`spring-mvc.xml`的拦截器配置中，添加对`/address/**`路径的拦截！

然后，创建`cn.jacob.store.controller.AddressController`，继承自`BaseController`，添加`@Controller`和`@RequestMapping("/address")`这2个注解，并声明`@Autowired private IAddressService addressService;`对象。

然后，在控制器类中添加处理请求的方法：

	@RequestMapping(value="/addnew.do", method=RequestMethod.GET)
	@ResponseBody
	public ResponseResult<Void> handleAddnew(
		Address address, HttpSession session) {
		// 获取uid
		// 将uid封装到address
		// 调用业务层执行增加
		// 返回
		return null;
	}

完成后，可通过`http://localhost:8080/jacobStore/address/addnew.do?recvName=XiaoLiu&recvProvince=330000&recvCity=330100&recvArea=330101`在浏览器进行测试，完成后，将请求类型限制为`POST`。


## 3. 收货地址管理

### 3.2. 显示收货地址列表

#### 3.2.1. 显示收货地址列表-持久层

在接口中声明：

	List<Address> getList(Integer uid);

配置映射，SQL语句是：

	SELECT 
		id, 
		recv_tag	AS	recvTag, 
		recv_name	AS	recvName, 
		recv_district	AS	recvDistrict, 
		recv_address	AS	recvAddress, 
		recv_phone	AS	recvPhone, 
		is_default	AS	isDefault
	FROM 
		t_address
	WHERE 
		uid=#{uid}		
	ORDER BY 
		is_default DESC, id DESC
	
#### 3.2.2. 显示收货地址列表-业务层

声明并实现与持久层相同的方法。

完成后，执行单元测试。

#### 3.2.3. 显示收货地址列表-控制层

此次并没有抛出新的异常，则无须处理异常。

分析需要处理的请求：

	请求路径：/address/list.do
	请求类型：GET
	请求参数：HttpSession
	响应方式：ResponseResult<List<Address>>
	是否拦截：是，登录拦截，但无需修改配置

则，处理请求的方法：

	@RequestMapping("/list.do")
	@ResponseBody 
	public ResponseResult<List<Address>> showList(HttpSession session) {
		// 1. 获取数据
		// 2. 创建返回值
		// 3. 将数据封装到返回值对象
		// 4. 执行返回
	}

### 3.3. 设置默认收货地址

#### 3.3.1. 设置默认收货地址-持久层

在接口中：

	Integer setNonDefault(Integer uid);

	Integer setDefault(Integer id);

	Address findAddressById(Integer id);

对应的SQL语句是：

	UPDATE t_address SET is_default=0 WHERE uid=?

	UPDATE t_address SET is_default=1 WHERE id=?

	SELECT * FROM t_address WHERE id=?

#### 3.3.2. 设置默认收货地址-业务层

先创建`AddressNotFoundException`异常类；

在接口中：

	void setDefaultAddress(Integer id, Integer uid) throws AddressNotFoundException, UpdateDataException;

在实现类中：

	public void setDefaultAddress(Integer id, Integer uid) {
		// 【1】检查数据是否归属用户
		// 可能抛出：AddressNotFoundException
		// 【2】将该用户的所有地址设置非默认
		// 可能抛出：UpdateDataException
		// 【3】将指定id的地址设置为默认
		// 可能抛出：UpdateDataException
	}

	private Address findAddressById(Integer id) {
		...
	}

	private void setNonDefault(Integer uid) {
		Integer rows = ...
		if (rows < 1) {
			throws new UpdateDataException("...");
		}
	}

	private void setDefault(id) {
		Integer rows = ...
		if (rows < 1) {
			throws new UpdateDataException("...");
		}
	}

## 基于Spring的事务

### 关于事务

事务（Transaction）是某个业务中需要执行的多次数据访问的集合，例如在“设置默认收货地址”时，该功能也称之为一个业务，一个业务可能涉及多次数据操作。

事务可以将多条数据操作形成一个整体，并且，在执行时，要么全部成功，要么全部失败，以保证数据的安全。

所以：当某个业务中涉及2次或更多次的增、删、改操作时（例如1次删除加上1次修改，或2次修改……），应该使用事务！

### 使用事务

在Spring案例中，当某个业务是需要以事务的方式来执行的，在方法之前添加`@Transactional`注解即可！

由Spring管理的事务，默认都是执行完毕后提交的，仅当执行过程中捕获到任何`RuntimeException`时自动回滚！

基于这种工作特性，在开发过程中，必须做法：

- 调用持久层访问数据时，所有的增、删、改操作必须判断受影响的行数，且，行数错误时必须抛出某种异常；

- 在业务层中抛出的异常必须是`RuntimeException`的子孙类；

并且，在Spring的配置文件中，必须配置：

	<!-- DataSourceTransactionManager -->
	<bean id="transactionManager"
		class="org.springframework.jdbc.datasource.DataSourceTransactionManager">
		<!-- 数据源 -->
		<property name="dataSource"
			ref="dataSource" />
	</bean>
	
	<!-- 注解驱动 -->
	<tx:annotation-driven 
		transaction-manager="transactionManager"/>
	

## 3. 收货地址管理

### 3.3. 设置默认收货地址

#### 3.3.3. 设置默认收货地址-控制器层

步骤1：是否需要处理新的异常？有：`AddressNotFoundException`、`AddressAccessException`，所以，需要在`BaseController`中进行处理。

步骤2：设计请求：

	请求路径：/address/set_default.do
	请求类型：不限
	请求参数：id(*)
	响应方式：ResponseResult<Void>
	是否拦截：是，登录拦截，无需修改配置

则处理请求的方法：

	@RequestMapping("/set_default.do")
	@ResponseBody
	public ResponseResult<Void> setDefault(
		@RequestParam("id") Integer id,
		HttpSession session) {
		Integer uid = getUidFromSession(session);
		addressService.setDefaultAddress(id, uid);
		return new ResponseResult<Void>();
	}

### 3.4. 删除收货地址

### 3.4.1. 删除收货地址-持久层

抽象方法：

	Integer deleteById(Integer id);

	Integer getMaxId(Integer uid);

SQL语句：

	DELETE FROM t_address WHERE id=?

	SELECT MAX(id) FROM t_address WHERE uid=?

### 3.4.2. 删除收货地址-业务层

抽象方法：

	void delete(Integer id, Integer uid);

业务分析：

	@Transactional
	根据id查询数据
	检查数据是否存在
		存在：检查数据的uid归属
			归属正常：执行删除
				判断刚才删除的地址是否是默认
				是：当前还有没有收货地址（数量多少）
					不为0：将id最大的数据设置为默认地址
					为0：不需要执行任何任务
				否：不需要执行任何任务
			归属错误：抛出异常AddressAccessException
		不存在：抛出异常AddressNotFoundException
	
代码实现：

	@Transactional
	public void delete(Integer id, Integer uid)
			throws AddressNotFoundException, AddressAccessException, DeleteDataException {
		// 根据id查询数据
		Address data = findAddressById(id);
		// 检查数据是否存在
		if (data != null) {
		    // 存在：检查数据的uid归属
		    if (data.getUid().equals(uid)) {
		        // 归属正常：执行删除
		    	deleteById(id);
		    	// 判断刚才删除的地址是否是默认
		    	if (data.getIsDefault() == 1) {
		            // 是：当前还有没有收货地址（数量多少）
		    		Integer count = getCountByUid(uid);
		    		if (count > 0) {
		                // 不为0：将id最大的数据设置为默认地址
		    			Integer maxId = getMaxId(uid);
		    			setDefault(maxId);
		    		}
		    	}
		    } else {
		        // 归属错误：抛出异常AddressAccessException
		    	throw new AddressAccessException(
		    		"尝试删除的收货地址数据归属错误！");
		    }
		} else {
		    // 不存在：抛出异常AddressNotFoundException
			throw new AddressNotFoundException(
				"尝试删除的收货地址数据不存在！");
		}
	}

### 3.4.3. 删除收货地址-控制器层

步骤1：是否需要处理新的异常？有：`DeleteDataException`，所以，需要在`BaseController`中进行处理。

步骤2：设计请求：

	请求路径：/address/delete.do
	请求类型：不限
	请求参数：id(*)
	响应方式：ResponseResult<Void>
	是否拦截：是，登录拦截，无需修改配置

则处理请求的方法：

	@RequestMapping("/delete.do")
	@ResponseBody
	public ResponseResult<Void> delete(
			@RequestParam("id") Integer id,
			HttpSession session) {
		Integer uid = getUidFromSession(session);
		addressService.delete(id, uid);
		return new ResponseResult<Void>();
	}

## 4. 主页热销排行

#### 4.1. 主页热销排行-持久层

为了使得查询商品列表的功能可以适用于多处，所以，在设计时，使用了更多参数，使得功能的运用可以更加灵活，在`GoodsMapper`接口中声明的抽象方法是：

	List<Goods> getList(
		@Param("where") String where,
		@Param("orderBy") String orderBy,
		@Param("offset") Integer offset,
		@Param("count") Integer count
	);

对应的SQL映射：

	SELECT 
		id, title, image, price
	FROM 
		t_goods
	<if test="where != null">
	WHERE 
		${where}
	</if>
	<if test="orderBy != null">
	ORDER BY 
		${orderBy}
	</if>
	<if test="offset != null">
	LIMIT 
		#{offset}, #{count}
	</if>

**关于#{}和${}**

在MyBatis的映射中，使用`#{}`表示的变量，是以前学习JDBC阶段使用问号(`?`)可以表示的内容，在处理过程中，会使用预编译的方式来进行处理，并且，无视数据类型，所以，在编写SQL语句时，即使某个变量的值是字符串类型的，也不需要写成`username='#{username}'`这种在两端添加单引号的语法。

使用`${}`表示的变量，是通过字符串的拼接形成的SQL语句，所以，如果使用它来表示字符串或其它例如时间等格式，可能存在两端的符号的问题。

一般，值都使用`#{}`格式的变量，这种格式无法表示SQL语句中的某个部分，例如包含字段名等等，对于这种需求，就需要使用`${}`格式的变量。

注意：由于使用`${}`格式的变量，最终在处理时只是单纯的拼接SQL语句，所以，可能存在SQL注入的风险！通常，关键部分的数据，是不允许提交相关特殊字符的，所以，如果对参数的字符时行了过滤，或者例如密码都是经过摘要运算加密过的，其中并不包括单引号(`'`)，就不会出现SQL注入的问题，所以，也不用太过于紧张关于SQL注入的问题！

	SELECT * FROM t_user WHERE
		username='chengheng' AND password='1234'

	SELECT * FROM t_user WHERE
		username='chengheng' AND password='1' OR '1'='1'

	username : chengheng
	password : 1' OR '1'='1

#### 4.2. 主页热销排行-业务层

创建`cn.jacob.store.service.IGoodsService`接口，声明抽象方法：

	List<Goods> getHotGoodsList();

创建`cn.jacob.store.service.GoodsServiceImpl`实现类，实现以上接口，添加`@Service("goodsService")`，声明`@Autowired private GoodsMapper goodsMapper`，然后，声明与持久层相同的方法，使用私有权限，直接调用即可：

	private List<Goods> getList(String where, String orderBy, Integer offset, Integer count) {
		return goodsMapper.getList(where, orderBy, offset, count);
	}

关于接口中抽象方法的实现：

	public List<Goods> getHotGoodsList() {
		return getList(null, "priority DESC", 0, 4);
	}

完成后，执行测试。









## 关于导入数据

进入MySQL控制台，通过`source d:/t_goods.sql`语法导入。

检查：

	SELECT id, title FROM t_goods LIMIT 0, 10;

	SELECT id, name FROM t_goods_category LIMIT 0, 10;

自带电脑的同学：使用工具

基于Linux的同学：新建记事本，粘贴SQL脚本，然后导入自行创建的记事本！不要执行`set names gbk;`，如果已经执行，则需要再次执行`set names utf8;`

## 4. 主页热销排行

#### 4.3. 主页热销排行-控制器层

分析请求：

	请求路径：/goods/hot_list.do
	请求类型：GET
	请求参数：无
	响应方式：ResponseResult<List<Goods>>
	是否拦截：否

则创建控制器类，完成基本步骤，并添加处理请求的方法：

	@RequestMapping("/hot_list.do")
	@ResponseBody
	public ResponseResult<List<Goods>> getHotList() {
		ResponseResult<List<Goods>> rr
			= new ResponseResult<List<Goods>>();
		List<Goods> list = goodsService.getHotGoodsList();
		rr.setData(list);
		return rr;
	}

#### 4.4. 主页热销排行-前端页面

当页面刚刚打开时（`$(document).ready()`）发出AJAX请求，并获取数据，最后显示在列表中（复制现有的HTML代码并使用数据进行替换）。

	<script type="text/javascript">
	$(document).ready(function() {
		var url = "../goods/hot_list.do";
		$.ajax({
			"url": url,
			"type": "GET",
			"dataType": "json",
			"success": function(json) {
				$("#hot-list").empty();
				
				var list = json.data;
				console.log("热销的4件商品：")
				for (var i = 0; i < list.length; i++) {
					console.log(list[i].title);
					
					var html = '<div class="col-md-12">'
						+ '<div class="col-md-9"><a href="product.html">#{goodsTitle}</a></div>'
						+ '<div class="col-md-3"><img src="..#{goodsImage}collect.png" height="50" /></div>'
						+ '</div>';
						
					html = html.replace(/#{goodsTitle}/g, list[i].title);
					html = html.replace(/#{goodsImage}/g, list[i].image);
					
					$("#hot-list").append(html);
				}
			}
		});
	});
	</script>

## 5. 显示商品详情

### 5.1. 显示商品详情-持久层

虽然原有的持久层中的`getList()`可以完成**根据id查询商品数据**的功能，但是，它查询的字段较少，不足以满足**显示商品详情**的需求，如果，一定去修改原有的`getList()`查询时的字段列表，又会导致该功能应用于**查询列表**时会查询更多的不必要的字段，会出现资源的浪费，所以，原有的`getList()`只用于各种列表的查询，而不通过它来实现详情的查询。

在持久层接口中添加新的抽象方法：

	Goods findGoodsById(String id);

然后，配置它的映射：

	SELECT 
		id, 
		category_id	AS	categoryId,
		item_type		AS	itemType,
		title,
		sell_point		AS	sellPoint,
		price,
		num,
		barcode,
		image,
		status,
		priority
	FROM 
		t_goods
	WHERE 
		id=?

### 5.2. 显示商品详情-业务层

该功能没有业务。

业务层公有的、用于组织业务的方法：

	public Goods getGoodsById(String id) { }

私有的、用于实现功能的方法：

	private Goods findGoodsById(String id);

### 5.3. 显示商品详情-控制器层

分析请求：

	请求路径：/goods/details.do
	请求类型：GET
	请求参数：id(*)
	响应方式：ResponseResult<Goods>
	是否拦截：否

则创建控制器类，完成基本步骤，并添加处理请求的方法：

	@RequestMapping("/details.do")
	@ResponseBody
	public ResponseResult<Goods> getDetails(
		@RequestParam("id") String id) {
		Goods goods = goodsService.getGoodsById(id);
		ResponseResult<Goods> rr
			= new ResponseResult<Goods>();
		rr.setData(goods);
		return rr;
	}

### 5.4. 显示商品详情-前端页面

前端页面的主要任务是：获取URL中的id，根据id查询数据，并将数据显示在界面中，此操作应该在页面打开时即执行（`#(document).ready()`），显示数据时，只需要将数据显示到对应的HTML标签中即可(`$("#tag").html(value)`)。

## 6. 购物车管理

### 6.1. 将商品添加到购物车

#### 6.1.1. 将商品添加到购物车-持久层

先确定购物车的数据表：

	CREATE TABLE t_cart (
		id INT AUTO_INCREMENT,
		uid INT NOT NULL,
		goods_id VARCHAR(200) NOT NULL,
		goods_num INT NOT NULL,
		created_time DATETIME,
		created_user VARCHAR(20),
		modified_time DATETIME,
		modified_user VARCHAR(20),
		PRIMARY KEY(id)
	) DEFAULT CHARSET=UTF8;

然后创建对应的实体类`cn.jacob.store.entity.Cart`，继承自`BaseEntity`。

创建持久层接口`cn.jacob.store.mapper.CartMapper`，并添加抽象方法：

	// 插入数据
	Integer insert(Cart cart);

	// 查询
	Cart findCartByUidAndGoodsId(
		@Param("uid") Integer uid, 
		@Param("goodsId") String goodsId);

	// 修改数量
	Integer updateGoodsNum(
		@Param("id") Integer id, 
		@Param("goodsNum") Integer goodsNum);

最后，配置以上抽象方法的映射，SQL语句大致是：

	INSERT INTO t_cart (uid, goods_id, goods_num) VALUES (?, ?, ?)

	SELECT id, goods_num FROM t_cart WHERE goods_id=? AND uid=?

	UPDATE t_cart SET goods_num=? WHERE id=?

#### 6.1.2. 将商品添加到购物车-业务层

创建业务层接口，添加抽象方法：

	void addToCart(Cart cart);

然后，创建业务层实现类，按常规步骤编写，并重写其中的抽象方法：

	public void addToCart(Cart cart) {
		// 根据cart参数中封装的uid和goodsId执行查询
		// 判断结果是否为null
			// 是：该用户此前没有添加该商品，则执行插入数据
			// 否：该用户已经添加该商品，获取原有数量
			// 从cart参数中获取此次的增量，并计算得到新的数量
			// 更新商品数量
	}





### 在HTML中获取URL中的参数

核心是通过Javascript中的`location.search`可以获取URL中从`?`开始，右侧的所有内容，例如URL是`http://localhost:8080/jacobStore/web/product.html?from=Beijing&id=9527&user=Jack`，则`location.search`的值是`?from=Beijing&id=9527&user=Jack`。

后续，根据`location.search`的结果进行分析，即可得到其中某些参数的值。

如果只需要获取某个指定名称的参数值，例如获取`id`值，或者`user`的值，推荐使用正则表达式来匹配，从而获取属性值，通常，基于jQuery进行封装：

	(function ($) {
		  $.getUrlParam = function (name) {
		   var reg = new RegExp("(^|&)" + name + "=([^&]*)(&|$)");
		   var r = window.location.search.substr(1).match(reg);
		   if (r != null) return unescape(r[2]); return null;
		  }
	})(jQuery);

经过以上代码后，可以通过`$.getUrlParam("id")`获取URL中名为`id`的属性的值，通过`$.getUrlParam("user")`获取URL中名为`user`的属性的值，使用这样的做法，在URL中的多个属性中，各属性并不区分前后顺序。

**注意：该函数只能获取指定名称的第1个参数值！即URL中的参数包含id=666&id=888&id=999时，通过以上函数，只能获取到666这1个值。**

#### 6.1.4. 将商品添加到购物车-前端页面

服务器端的控制器所需要的请求参数包括：`goods_id`、`goods_num`，应该在商品详情页点击“加入购物车”时发出请求，并提交这2个参数即可，如果用户没有登录，则还需要先登录！

商品id在加载页面时，已经从URL中获取了，所以，将此前的商品id声明为全局变量，由于加载页面时已经完成赋值，所以，在“加入购物车”时，直接使用全局变量的id即可用于表示商品的id。

除了商品id以外，还需要提交到服务器端的数据就只有商品数量了，没有必要专门添加一个`<form>`再通过`#("form-id").serialize()`来提交，直接拼接出`goods_id=xx&goods_num=xx`参数即可。

另外，此次操作是需要登录的，所以，在处理AJAX时，还要添加`error`配置，以免被服务器端的拦截器拦截后响应结果是重定向。

	// 点击“加入购物车”时
	$("#btn-add-to-cart").click(function() {
		var url = "../cart/add.do";
		var goodsNum = $("#num").val();
		var data = "goods_id=" + id 
				+ "&goods_num=" + goodsNum;
		console.log(data);
		$.ajax({
			"url": url,
			"data": data,
			"type": "POST",
			"dataType": "json",
			"success": function(json) {
				if (json.state == 200) {
					alert("操作成功！");
				} else {
					alert("操作失败！" + json.message);
				}
			},
			"error": function(xhr) {
				console.log("响应码：" + xhr.status);
				alert("您的登录信息已过期，请重新登录！");
				location.href = "login.html";
			}
		});
	});

### 6.2. 显示购物车列表

#### 6.2.1. 显示购物车列表-持久层

通常，为了规范的设计数据表，所以，可能在数据库存储了一些外链，即其它表中的id，而并没有存储实际的数据，并且，实体类都是与数据表对应的，所以，涉及多张表的查询时，实体类并不适合作为查询的结果类型，则需要另创建VO类来表示查询结果。

购物车数据就是存在关键查询的，所以，需要查询的结果能直接显示出所需要显示的数据，则需要有对应的VO类，则创建`cn.jacob.store.vo.CartVO`类：

	public class CartVO implements Serializable {

		private static final long serialVersionUID = -4226267978903049502L;

		private Integer cartId;
		private Integer uid;
		private String goodsId;
		private String goodsTitle;
		private String goodsImage;
		private Long goodsPrice;
		private Integer goodsNum;

		// SET/GET方法
	}

关于VO类的属性设计，可以根据查询、显示的需求来决定。

然后，在持久层接口中声明抽象方法时，查询结果的类型就是VO类的类型：

	List<CartVO> getList(Integer uid);

需要执行的SQL语句：

	SELECT 
		c.id	AS	cartId,
		c.uid,
		c.goods_id	AS	goodsId,
		c.goods_num	AS	goodsNum,
		g.title	AS	goodsTitle,
		g.image	AS	goodsImage,
		g.price	AS	goodsPrice
	FROM 
		t_cart AS c
	INNER JOIN
		t_goods AS g
	ON 
		c.goods_id=g.id
	WHERE
		c.uid=#{uid};

以上查询，也可以通过`SELECT xx FROM 表1,表2 WHERE 表1.xx=表2.xx`此类的语法来实现，但是，不推荐这种语法。

#### 6.2.2. 显示购物车列表-业务层

通常，查询并直接显示的功能，没有太多业务逻辑需要设计，所以，业务层的设计相对比较简单，首先，在接口中声明公有的、组织业务的方法：

	List<CartVO> getCartListByUid(Integer uid);

然后，在实现类实现以上方法，且，实现类应该添加私有的、执行数据访问的方法：

	private List<CartVO> getList(Integer uid) {
		return cartMapper.getList(uid);
	}

	public List<CartVO> getCartListByUid(Integer uid) {
		return getList(uid);
	}

#### 6.2.3. 显示购物车列表-控制器层

在控制器类中添加处理请求的方法：

	@RequestMapping("/list.do")
	@ResponseBody
	public ResponseResult<List<CartVO>> getCartListByUid(
		HttpSession session) {
		// 获取uid
		// 执行
		// 创建返回值对象
		// 封装数据
		// 返回
	}

#### 6.2.4. 显示购物车列表-前端页面

显示数据的前端页面是`cart.html`。

由于该页面是必须登录才可以访问的，所以，无需调整`HtmlAccessFilter`。

在页面刚刚加载时（`$(document).ready()`）就应该请求数据列表，先请求到所需的数据，并显示在控制台，表示测试。

如果能够成功获取数据，则找出`cart.html`中显示列表的HTML代码，声明为Javascript中的模版，并将其中需要替换的内容使用占位符表示，在遍历查询到的数据结果时，替换占位符，并添加到列表的容器对象中，即可完成显示。

以上流程，可参考`index.html`中的热销列表。

### 6.3. 修改购物车商品数量

#### 6.3.1. 修改购物车商品数量-持久层

由于持久层中已经存在：

	Integer updateGoodsNum(
		@Param("id") Integer id, 
		@Param("goodsNum") Integer goodsNum);

通过该方法即可实现商品数量的修改，所以，本次无须重新开发修改的功能。

由于后续功能需要**根据购物车数据id进行查询**的功能，所以，在持久层添加新的抽象方法：

	Cart findCartById(Integer id);

然后配置以上方法的映射。

#### 6.3.2. 修改购物车商品数量-业务层

在修改商品数量时，可能抛出2种新的异常：`CartNotFoundException`、`GoodsNumLimitException`，所以，需要创建这2个新的异常类。

可以在业务层接口中添加2个新的抽象方法：

**方法1：将商品数量+1**

购物车数据id应该在用户提交请求时，由用户提交。

用户提交的商品数量只是增量而已，而不是运算得到的新数量，所以，应该先根据购物车数据id查询数据，获取原数量，结合增量，得到新数量。

执行`updateGoodsNum(购物车数据id，商品新数量)`

所以，在业务层接口中添加抽象方法：

	void addNum(Integer id);

在实现类中：

	private Cart findCartById(Integer id) {
		return cartMapper.findCartById(id);
	}

	public void addNum(Integer id) {
		Cart cart = findCartById(id);
		if (cart == null) {
			throw new CartNotFoundException(
				"尝试访问的购物车数据不存在！");
		}
		Integer num = cart.getGoodsNum() + 1;
		updateGoodsNum(id, num);
	}

**方法2：将商品数量-1**

实现思路与方法1基本相同，在业务层接口中添加抽象方法：

	void reduceNum(Integer id);

在实现类中：

	public void reduceNum(Integer id) {
		Cart cart = findCartById(id);
		if (cart == null) {
			throw new CartNotFoundException(
				"尝试访问的购物车数据不存在！");
		}
		if(cart.getGoodsNum() <= 1) {
			throw new GoodsNumLimitException(
				"尝试修改的购物车数据的商品数量招出限制！");
		}
		Integer num = cart.getGoodsNum() - 1;
		updateGoodsNum(id, num);
	}

#### 6.3.3. 修改购物车商品数量-控制器层

由于业务层抛出了新的异常，应该在`BaseController`中对这2种新的异常进行处理。

在控制器层添加2个方法：

	@RequestMapping("add_num.do")
	@ResponseBody
	public ResponseResult<Void> addGoodsNum(
		@RequestParam("id") Integer id) {
		cartService.addNum(id);
		return new ResponseResult<Void>();
	}

	@RequestMapping("reduce_num.do")
	@ResponseBody
	public ResponseResult<Void> reduceGoodsNum(
		@RequestParam("id") Integer id) {
		cartService.reduceNum(id);
		return new ResponseResult<Void>();
	}

完成后，通过`http://localhost:8080/jacobStore/cart/add_num.do?id=10`这类URL在浏览器中进行测试。

#### 6.3.4. 修改购物车商品数量-前端页面

首先，需要为加号、减号按钮绑定事件，在AJAX获取到购物车数据，生成HTML代码时，配置`onclick="add(#{cartId})"`：

	<input type="button" value="+" class="num-btn" onclick="add(#{cartId})" />

由于需要访问到显示商品数量的输入框，需要为输入框添加id：

	<input id="goods-num-#{cartId}" type="text" size="2" readonly="readonly" class="num-text" value="#{goodsNum}">

且右侧的`span`标签中还需要显示每项商品的总价，页面加载时、加减数量时都需要显示总价，则这个标签也需要id：

	<span id="goods-total-#{cartId}">#{goodsTotalPrice}</span>

在加载页面时显示每项商品的总价：

	html = html.replace(/#{goodsTotalPrice}/g, list[i].goodsPrice * list[i].goodsNum);

然后，编写“增加数量”的函数：

	function add(id){
		// alert("add:" + id);
		var url = "../cart/add_num.do";
		var data = "id=" + id;
		$.ajax({
			"url": url,
			"data": data,
			"type": "GET",
			"dataType": "json",
			"success": function(json) {
				if (json.state == 200) {
					// 输入框中的数量：取出原数量，并+1
					var n = parseInt($("#goods-num-" + id).val()) + 1;
					$("#goods-num-" + id).val(n);
					// 显示单项商品的总价
					var p = parseInt($("#goods-price-" + id).html());
					var total = p * n;
					$("#goods-total-" + id).html(total);
				} else {
					alert("操作失败！" + json.message)
				}
			},
			"error": function(xhr) {
				console.log("响应码：" + xhr.status);
				alert("您的登录信息已过期，请重新登录！");
				location.href = "login.html";
			}
		});
	}

关于“减少数量”，做法类似，则课后自行完成！

### 7. 显示确认订单

将由“购物车列表”页的勾选，并提交后，显示“确认订单”，需要的：

1. 在购物车列表页：约104行，为`<form>`标签添加`method`和`action`属性：

	<form method="get" action="orderConfirm.html" role="form">

2. 在购物车列表页，“提交”按钮的类型应该是`type="submit"`

3. 在生成列表项时，每个`<input type="checkbox" ... />`都必须配置`name`和`value`，且`value`值应该是每条数据的id，使用占位符，后续会被替换：
	```
	<input name="cart_id" value="#{cartId}" type="checkbox" class="ckitem" />
	```

**需下载新的静态页面V2.0，解压后，覆盖到项目中之前，先删除js/product.js文件！**

在“确认订单”页面，需要使用到的功能有：

1. 获取当前用户的所有收货地址数据，以显示在`<select>`下拉列表中；

2. 获取选中的`cart_id`对应的购物车数据，显示在需要确认的商品列表中。

**功能1：显示收货地址列表**

此前，已经完成了“获取当前登录的用户的收货地址列表”功能，在`AddressController`中已经设计了`/address/list.do`请求路径，可以通过这个请求路径获取收货地址列表，则无须重新开发，直接请求这个路径，获取数据即可！

当前页面（确认订单页面）是必须登录的，所以，无须修改`HtmlAccessFilter`中的白名单。

**功能2：显示选中的购物车数据列表**

需要“根据多个id查询购物车中的数据的列表”功能，则应该先在持久层开发该功能：

	List<CartVO> getListByIds(Integer[] ids);

	<select id="getListByIds" resultType="xx.xx.xx.CartVO">
		SELECT 
			c.id	AS	cartId,
			c.uid,
			c.goods_id	AS	goodsId,
			c.goods_num	AS	goodsNum,
			g.title	AS	goodsTitle,
			g.image	AS	goodsImage,
			g.price	AS	goodsPrice
		FROM 
			t_cart AS c
		INNER JOIN
			t_goods AS g
		ON 
			c.goods_id=g.id
		WHERE
			c.id IN (
			<foreach collection="array" 
				item="id" separator=",">
			#{id}
			</foreach>
			)
	</select>

后续，参考此前的模式完成业务层和控制器层即可。

然后，在前端页面中，当页面加载完成时，获取URL中的`cart_id`的值，并组织成数组，然后再次发出AJAX请求获取数据。

关于`cart_id`的获取，首先，不可以通过`$.getUrlParam()`函数去获取，因为，这个函数只能获取多个同名参数中的第1个参数值！对于参数为`cart_id=9&cart_id=10&cart_id=11`此类URL，只能自行编写程序来获取：

	// 获取网址中的参数部分，不需要问号，所以，调用substring(1)进行截取
	var params = location.search.substring(1);
	// 组织本次需要提交的参数
	var data = "";
	// 将当前URL中的参数拆成数组
	var paramArray = params.split("&");
	// 遍历数组 
	for (var i = 0; i< paramArray.length; i++) {
		// 将每一组参数(cart_id=8)再拆成数组
		var arr = paramArray[i].split("=");
		// 判断参数名称
		if (arr[0] == "cart_id") {
			// 参数名为cart_id，则获取值
			data += "&ids=" + arr[1];
		}
	}
	data = data.substring(1);

处理好参数后，则发出请求，获取结果，显示，完成。

## 订单表

	CREATE TABLE t_order (
		id INT AUTO_INCREMENT,
		uid INT NOT NULL,
		recv_name
		recv_phone
		recv_district
		recv_address
		recv_zip
		pay
		status
		order_time	
		pay_time
		// 4个日志
		PRIMARY KEY(id)
	) DEFAULT CHARSET=UTF8;

	CREATE TABLE t_order_item (
		id INT AUTO_INCREMENT,
		order_id INT NOT NULL,
		goods_id
		goods_image
		goods_title
		goods_price
		goods_num
		// 4个日志
		PRIMARY KEY(id)
	) DEFAULT CHARSET=UTF8;

## 8. 创建订单

### 8.1. 创建订单-持久层

**数据表**

订单的数据中，存在“1个订单中可以有多样商品”的关系，即“订单”与“订单中的商品的种类”是1对多的关系，所以，只使用1张数据表是无法存储订单相关信息的，就需要“订单表”和“订单商品表”这2张数据表来完成存储！

订单中的某些数据一旦产生，将不会随着后续数据的变化而再次调整，例如价格，下单时确定了价格以后，无论后续商品的价格如何调整，此订单中的商品价格是不会再次发生变化的，所以，在存储时，应该把价格直接存储在订单相关的表中，而不是通过商品的id关联到商品表再查询！此类的数据还包括：收货人的相关信息、商品的完整信息等。

订单的总价格应该是将汇总数据直接存储的，在实际应用中，总价格不一定与商品数量和单价对应， 因为还可能存在各种优惠减免的情况。

创建数据表：

	CREATE TABLE t_order (
		id INT AUTO_INCREMENT,
		uid INT NOT NULL,
		recv_name VARCHAR(16) NOT NULL,
		recv_phone VARCHAR(20) NOT NULL,
		recv_district VARCHAR(30) NOT NULL,
		recv_address  VARCHAR(50) NOT NULL,
		recv_zip CHAR(6),
		pay BIGINT(20) NOT NULL,
		status INT NOT NULL,
		order_time DATETIME NOT NULL,
		pay_time DATETIME,
		created_time DATETIME,
		created_user VARCHAR(20),
		modified_time DATETIME,
		modified_user VARCHAR(20),
		PRIMARY KEY(id)
	) DEFAULT CHARSET=UTF8;

	CREATE TABLE t_order_item (
		id INT AUTO_INCREMENT,
		order_id INT NOT NULL,
		goods_id VARCHAR(200) NOT NULL,
		goods_image VARCHAR(500) NOT NULL,
		goods_title VARCHAR(100) NOT NULL,
		goods_price BIGINT(20) NOT NULL,
		goods_num INT NOT NULL,
		created_time DATETIME,
		created_user VARCHAR(20),
		modified_time DATETIME,
		modified_user VARCHAR(20),
		PRIMARY KEY(id)
	) DEFAULT CHARSET=UTF8;

**实体类**

实体类是与数据表一一对应的，所以，与订单相关的数据表有2张，则实体类也应该是2个。

当然，这样的实体类可能不便于表示数据，后续可以通过VO类来使用！

**接口与抽象方法**

通常，每张数据表的操作都对应了持久层中的1个接口，而此次的订单数据处理时，“订单商品表”通常不会单独访问，而是随着“订单表”一起进行数据操作，例如：创建订单时，一并创建订单商品中的数据，或，删除订单时，也应该删除订单商品中的数据……所以，没有必要创建`OrderItemMapper.java`，原本希望设计在这个接口中的方法直接设计在`OrderMapper.java`中就可以了。

所以，创建`cn.jacob.store.mapper.OrderMapper`接口，声明抽象方法：

	// 创建订单
	Integer insertOrder(Order order);

	// 创建订单商品
	Integer insertOrderItem(OrderItem orderItem);

注意：每个抽象方法应该只对应1条需要执行的SQL指令，尽管“创建订单”应该至少有2条SQL指令，但是，功能的组织应该在业务层中完成！

**XML映射**

复制并得到`OrderMapper.xml`，配置以上2个抽象方法的映射。

### 8.2. 创建订单-业务层

**前序任务**

实现“根据收货地址id，查询收货地址详情”的功能，其业务方法为：

	Address getAddressById(Integer id);

**创建订单**

关于“创建订单”，可以由用户提供的数据就是业务层方法的参数，有：收货地址id，若干个购物车数据id，及当前登录的用户的id。则，业务中的方法：

	void createOrder(Integer uid, Integer addressId, Integer[] cartIds);

然后，创建实现类`cn.jacob.store.service.impl.OrderServiceImpl`：
	
	@Autowired private IAddressService addressService;
	@Autowired private ICartService cartService;

	@Transactional
	public void createOrder(Integer uid, Integer addressId, Integer[] cartIds) {
		// 获取当前时间
		Date now = new Date();
		
		// 根据cartIds获取商品相关数据
		List<CartVO> carts = cartService.getListByIds(uid, cartIds);
		// 计算总金额
		Long pay = 0L;
		for (CartVO cartVO : carts) {
			pay += cartVO.getGoodsPrice() * cartVO.getGoodsNum();
		}

		// 根据addressId获取收货地址数据
		Address address = addressService.getAddressById(addressId);
		// 准备插入订单数据
		Order order = new Order();
		order.setUid(uid);
		order.setRecvName(address.getRecvName());
		// 类似，封装收货数据
		order.setStatus(0); // 0-未支付
		order.setOrderTime(now);
		order.setPayTime(null);
		order.setPay(pay);

		// 执行：插入订单数据
		insertOrder(order);

		// 执行：插入订单商品数据
		for (CartVO cartVO : carts) {
			OrderItem item = new OrderItem();
			item.setOrderId(order.getId());
			item.setGoodsId(cartVO.getGoodsId());
			// 类似，封装商品数据
			insertOrderItem(item);
		}

		// TODO 根据参数Integer[] cartIds读取到的goods_id和goods_num，更新t_goods表中商品的库存

		// TODO 根据参数Integer[] cartIds删除购物车中对应的数据
	}

	private void insertOrder(Order order) {
	}

	private void insertOrderItem(OrderItem orderItem) {
	}

### 8.3. 创建订单-控制器层

创建`cn.jacob.store.controller.OrderController`类，添加处理请求的方法：

	@RequestMapping(value="/create.do", method=RequestMethod.POST)
	@ResponseBody
	public ResponseResult<Void> createOrder(
		@RequestParam("address_id") Integer addressId,
		@RequestParam("cart_ids") Integer[] cartIds,
		HttpSession session) {
		// 获取uid
		// 调用业务层实现功能
		// 返回
	}


### 8.4. 创建订单-前端页面

前端页面使用`<form>`表单和`<input type="submit" ... />`提交按钮即可提交数据，其中，`Integer[] cartIds`可以使用`<input type="hidden" name="cartIds" value="xx" />`隐藏域来提交。

## 查询订单

由于一个完整的订单数据需要“订单表”和“订单商品表”中的数据共同构成，且订单表中的数据与订单商品表中的数据是1对多的关系，在查询时，需要使用关联查询：

	SELECT
		*
	FROM 
		t_order
	INNER JOIN
		t_order_item
	ON
		t_order.id = t_order_item.order_id
	WHERE
		t_order.id=1;

并且，实体类无法表示查询结果，则应该创建VO类来表示查询结果：

	public class OrderVO implements Serializable {
	
		private static final long serialVersionUID = 310521494455105831L;
	
		private Integer id;
		private Integer uid;
		private String recvName;
		private String recvPhone;
		private String recvDistrict;
		private String recvAddress;
		private String recvZip;
		private Long pay;
		private Integer status;
		private Date orderTime;
		private Date payTime;
		private List<OrderItem> orderItems;
		
		// ...

	}

并且，在查询时，必须配置`<resultMap>`来确定1对多的数据结果将如何存储到VO类的对象中：

	<resultMap id="OrderMap" 
		type="cn.jacob.store.vo.OrderVO">
		<id column="oid" property="id" />
		<result column="uid" property="uid" />
		<result column="recv_name" property="recvName" />
		<result column="recv_phone" property="recvPhone" />
		<result column="recv_district" property="recvDistrict" />
		<result column="recv_address" property="recvAddress" />
		<result column="recv_zip" property="recvZip" />
		<result column="pay" property="pay" />
		<result column="status" property="status" />
		<result column="order_time" property="orderTime" />
		<result column="pay_time" property="payTime" />
		<collection property="orderItems"
			ofType="cn.jacob.store.entity.OrderItem">
			<id column="oiid" property="id" />
			<result column="order_id" property="orderId" />
			<result column="goods_id" property="goodsId" />
			<result column="goods_title" property="goodsTitle" />
			<result column="goods_image" property="goodsImage" />
			<result column="goods_price" property="goodsPrice" />
			<result column="goods_num" property="goodsNum" />
		</collection>
	</resultMap>

	<!-- 根据订单id查询订单详情 -->
	<!-- OrderVO getOrderById(Integer orderId) -->
	<select id="getOrderById"
		resultMap="OrderMap">
		SELECT
			o.id AS oid,
			o.uid,
			recv_name, recv_phone,
			recv_district, recv_address,
			recv_zip,
			pay, status,
			order_time, pay_time,
			oi.id AS oiid,
			order_id,
			goods_id,
			goods_title, goods_image,
			goods_price, goods_num
		FROM 
			t_order AS o
		INNER JOIN
			t_order_item AS oi
		ON
			o.id = oi.order_id
		WHERE
			o.id=#{orderId};
	</select>

**如果对<resultMap>的配置不熟悉，可参考MYBATIS阶段DAY02的笔记中的图示。**

测试以上查询的结果例如：

	OrderVO [
		id=1, uid=3, 
		recvName=小王女士, 
		recvPhone=13800138001, 
		recvDistrict=浙江省, 舟山市, 嵊泗县, 
		recvAddress=高新小区, 
		recvZip=, 
		pay=410310, 
		status=0, 
		orderTime=Thu Dec 13 11:03:33 CST 2018, 
		payTime=null, 
		orderItems=[
			OrderItem [id=1, orderId=1, goodsId=10000042, goodsImage=/images/portal/21ThinkPad_New_S1/, goodsTitle=联想ThinkPad New S1（01CD） i5 6代 红色, goodsPrice=4399, goodsNum=60], 
	
			OrderItem [id=2, orderId=1, goodsId=10000022, goodsImage=/images/portal/13LenovoIdeaPad310_black/, goodsTitle=联想（Lenovo）IdeaPad310经典版黑色, goodsPrice=5119, goodsNum=20], 
	
			OrderItem [id=3, orderId=1, goodsId=100000424, goodsImage=/images/portal/21ThinkPad_New_S1/, goodsTitle=联想ThinkPad New S1（01CD） i5 6代 蓝色, goodsPrice=4399, goodsNum=10]
		]
	]

## Spring AOP

Spring AOP指的是“面向切面的编程”，它将数据的处理流程比喻成一条线，例如：控制器 > 业务层 > 持久层，每个功能的数据处理都是使用相同的处理流程，在这个过程中，可能有某些任务是公共的，即无论处理哪项数据的功能，都需要执行相同的任务，那么，面向切面的意思就是在这个过程中产生一个切入点，并确定切入点需要执行的代码，后续，每个数据处理流程都会执行相同的代码，就是面向切面的编程了。

AOP并不是Spring独有的特性！只是Spring框架提供了简便的实现AOP的编码方式。

关于使用，首先，需要添加相关依赖：

	<!-- AOP -->
	<dependency>
		<groupId>aspectj</groupId>
		<artifactId>aspectj-tools</artifactId>
		<version>1.0.6</version>
	</dependency>

	<dependency>
		<groupId>aspectj</groupId>
		<artifactId>aspectjweaver</artifactId>
		<version>1.5.4</version>
	</dependency>

**由于使用的是基于Spring的AOP，所以，还需要spring-webmvc依赖，如果项目已经应用Spring框架，则无需重复添加spring-webmvc依赖。**

然后，需要在Spring的配置文件中开启AOP的自动代理：

	<!-- 开启自动代理 -->
	<aop:aspectj-autoproxy />

然后，编写切面类，实现切面效果：

	@Component
	@Aspect
	public class TimeElapsedAspect {
	
		private long startTime;
		
		@Around("execution(* cn.jacob.store.service.impl.*.*(..))")
		public Object around(ProceedingJoinPoint pjp) throws Throwable {
			// 执行前序任务
			doBefore();
			
			// 调用原本应该执行的方法
			Object result = pjp.proceed();
			
			// 执行后续任务
			doAfter();
			
			// 返回原本应该执行的方法的返回值
			return result;
		}
		
		public void doBefore() {
			System.out.println("TimeElapsedAspect.doBefore()");
			startTime = System.currentTimeMillis();
		}
		
		public void doAfter() {
			long endTime = System.currentTimeMillis();
			long elapsed = endTime - startTime;
			System.out.println("TimeElapsedAspect.doAfter() : " + elapsed);
		}
		
	}

以上代码中，`@Around("execution(* cn.jacob.store.service.impl.*.*(..))")`注解中的配置，表示**无论是哪种返回值，只要是在cn.jacob.store.service.impl包下的任类（第1个星号）中的任何方法（第2个星号），且无论是什么参数（两个小数点）**，都满足切面的执行前提，所以，后续，在执行这个包中的任何类中的任何业务方法时，都会按照`@Around`对应的方法流程来进行处理！
















还需要添加以下辅助方法：

	private User insert(User user) {
		// 在参数user中封装那些不由外部提供的数据：
		// 1. 生成随机盐，并封装到user中
		// 2. 取出user中原密码执行加密，并封装回user中
		// 3. 设置isDelete为0
		// 4. 日志的4项

		// 调用持久层对象的方法实现功能，并获取返回值
		// 判断返回值是否为1
			// 是：返回参数对象 
			// 否：抛出InsertDataException异常
	}

	private User findUserByUsername(String username) {
		// TODO 检查用户名基本格式是否正确
		// 调用持久层对象的方法实现功能
	}

	private String getEncrpytedPassword(String password, String salt) {
		// 将原密码加密
		// 将盐加密
		// 将以上2个加密结果拼接
		// 循环5次加密
		// 返回
	}

完成后，执行单元测试。
