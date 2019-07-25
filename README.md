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

# 学子商城项目

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
